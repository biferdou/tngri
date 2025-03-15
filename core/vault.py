"""
Core vault functionality for the Tngri Password Manager.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

# Import internal modules
from core.crypto import derive_key, encrypt_data, decrypt_data
from utils.session import VaultSession
from models.schemas import DEFAULT_VAULT_STRUCTURE

logger = logging.getLogger("tngri.vault")


class TngriVault:
    """
    Secure password manager that encrypts and stores passwords locally.
    Uses PBKDF2 for key derivation and Fernet for symmetric encryption.
    """
    
    # Version of the vault format
    VERSION = "1.0.0"
    
    def __init__(self, vault_path: Optional[str] = None, timeout_minutes: int = 5):
        """
        Initialize the password vault.
        
        Args:
            vault_path: Path to the vault file (default: ~/.tngri/vault.dat)
            timeout_minutes: Minutes until session automatically locks
        """
        self.vault_path = vault_path or os.path.expanduser("~/.tngri/vault.dat")
        self.vault_dir = os.path.dirname(self.vault_path)
        self.salt_path = os.path.join(self.vault_dir, "salt.dat")
        self.config_path = os.path.join(self.vault_dir, "config.json")
        
        # Initialize vault data structure with defaults
        self.vault_data = DEFAULT_VAULT_STRUCTURE.copy()
        
        # Encryption setup
        self.key = None
        self.fernet = None
        
        # Config with defaults
        self.config = {
            "timeout_minutes": timeout_minutes,
            "clipboard_clear_seconds": 30,
            "backup_enabled": True,
            "backup_count": 5,
            "password_history_count": 3
        }
        
        # Create vault directory if it doesn't exist
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir)
            
        # Load config if it exists
        self._load_config()
        
        # Create session manager
        self.session = VaultSession(self.config["timeout_minutes"])
    
    def _load_config(self) -> None:
        """Load configuration from config file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as config_file:
                    loaded_config = json.load(config_file)
                    # Update config with loaded values
                    self.config.update(loaded_config)
                    logger.debug("Configuration loaded successfully")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
    
    def _save_config(self) -> None:
        """Save configuration to config file."""
        try:
            with open(self.config_path, 'w') as config_file:
                json.dump(self.config, config_file, indent=2)
            logger.debug("Configuration saved successfully")
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
    
    def setup(self, master_password: str) -> bool:
        """
        Set up a new vault with a master password.
        
        Args:
            master_password: The master password for the vault
            
        Returns:
            bool: True if setup was successful
        """
        try:
            # Generate a new salt
            salt = os.urandom(16)
            
            # Save the salt
            with open(self.salt_path, 'wb') as salt_file:
                salt_file.write(salt)
            
            # Generate encryption key from master password
            self.key = derive_key(master_password, salt)
            
            # Initialize vault data
            now = datetime.now().isoformat()
            self.vault_data = {
                "version": self.VERSION,
                "entries": {},
                "categories": {
                    "Uncategorized": {
                        "description": "Default category", 
                        "created": now
                    }
                },
                "metadata": {
                    "created": now,
                    "last_modified": now,
                    "last_accessed": now
                }
            }
            
            # Save the vault
            self.save_vault()
            
            # Unlock session
            self.session.unlock()
            
            logger.info("New vault created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error setting up vault: {e}")
            return False
    
    def unlock(self, master_password: str) -> bool:
        """
        Unlock the vault with the master password.
        
        Args:
            master_password: The master password for the vault
            
        Returns:
            bool: True if unlock was successful
        """
        try:
            if not os.path.exists(self.vault_path) or not os.path.exists(self.salt_path):
                logger.warning("Vault not found")
                return False
            
            # Read the salt
            with open(self.salt_path, 'rb') as salt_file:
                salt = salt_file.read()
            
            # Derive key from master password
            self.key = derive_key(master_password, salt)
            
            # Try to decrypt the vault
            try:
                self._load_vault()
                
                # Update last accessed time
                self.vault_data["metadata"]["last_accessed"] = datetime.now().isoformat()
                self.save_vault()
                
                # Unlock session
                self.session.unlock()
                
                logger.info("Vault unlocked successfully")
                return True
                
            except Exception as e:
                logger.error(f"Error decrypting vault: {e}")
                return False
                
        except Exception as e:
            logger.error(f"Error unlocking vault: {e}")
            return False
    
    def _load_vault(self) -> None:
        """
        Load and decrypt the vault data.
        
        Raises:
            Exception: If decryption fails or vault data is invalid
        """
        if not os.path.exists(self.vault_path):
            self.vault_data = DEFAULT_VAULT_STRUCTURE.copy()
            return
        
        with open(self.vault_path, 'rb') as vault_file:
            encrypted_data = vault_file.read()
        
        if not encrypted_data:
            raise ValueError("Vault file is empty")
        
        # Decrypt the vault data
        decrypted_data = decrypt_data(encrypted_data, self.key)
        self.vault_data = json.loads(decrypted_data)
        
        # Migrate older vault formats if needed
        if "version" not in self.vault_data:
            self._migrate_vault_format()
    
    def _migrate_vault_format(self) -> None:
        """Migrate older vault formats to the current version."""
        # Migrate from pre-versioned format
        old_data = self.vault_data
        now = datetime.now().isoformat()
        
        self.vault_data = {
            "version": self.VERSION,
            "entries": old_data,
            "categories": {
                "Uncategorized": {
                    "description": "Default category", 
                    "created": now
                }
            },
            "metadata": {
                "created": now,
                "last_modified": now,
                "last_accessed": now
            }
        }
        logger.info("Migrated vault from pre-versioned format")
    
    def save_vault(self) -> None:
        """Encrypt and save the vault data."""
        try:
            # Update last modified time
            self.vault_data["metadata"]["last_modified"] = datetime.now().isoformat()
            
            # Create backup before saving if enabled
            if self.config["backup_enabled"]:
                self._create_backup()
            
            # Encrypt and save the vault data
            encrypted_data = encrypt_data(json.dumps(self.vault_data), self.key)
            
            with open(self.vault_path, 'wb') as vault_file:
                vault_file.write(encrypted_data)
                
            logger.debug("Vault saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving vault: {e}")
            raise
    
    def _create_backup(self, suffix: str = None) -> None:
        """
        Create a backup of the vault file.
        
        Args:
            suffix: Optional suffix for the backup filename
        """
        if not os.path.exists(self.vault_path):
            return
            
        try:
            # Create backups directory if it doesn't exist
            backup_dir = os.path.join(self.vault_dir, "backups")
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
            
            # Generate backup filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            suffix_str = f"_{suffix}" if suffix else ""
            backup_path = os.path.join(backup_dir, f"vault_{timestamp}{suffix_str}.dat")
            
            # Copy vault file to backup
            with open(self.vault_path, 'rb') as src, open(backup_path, 'wb') as dst:
                dst.write(src.read())
                
            # Limit number of backups
            self._prune_backups()
            
            logger.debug(f"Backup created at {backup_path}")
            
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
    
    def _prune_backups(self) -> None:
        """Limit the number of backups to the configured maximum."""
        try:
            backup_dir = os.path.join(self.vault_dir, "backups")
            if not os.path.exists(backup_dir):
                return
                
            # Get list of backups sorted by modification time
            backups = sorted(
                [os.path.join(backup_dir, f) for f in os.listdir(backup_dir) if f.startswith("vault_")],
                key=os.path.getmtime
            )
            
            # Remove oldest backups if we exceed the limit
            while len(backups) > self.config["backup_count"]:
                oldest = backups.pop(0)
                os.remove(oldest)
                logger.debug(f"Removed old backup: {oldest}")
                
        except Exception as e:
            logger.error(f"Error pruning backups: {e}")
    
    def add_entry(self, service: str, username: str, password: str, 
                 notes: str = "", url: str = "", category: str = "Uncategorized",
                 tags: List[str] = None) -> bool:
        """
        Add a new password entry to the vault.
        
        Args:
            service: Service name
            username: Username
            password: Password
            notes: Additional notes
            url: Website URL
            category: Category name
            tags: List of tags
            
        Returns:
            bool: True if entry was added successfully
        """
        try:
            # Check session
            if self.session.is_locked():
                logger.warning("Session is locked")
                return False
                
            self.session.activity()
            
            # Validate category
            if category not in self.vault_data["categories"]:
                # Create new category
                self.add_category(category)
            
            # Check if entry already exists
            if service in self.vault_data["entries"]:
                logger.warning(f"Entry for '{service}' already exists")
                return False
            
            # Create entry
            now = datetime.now().isoformat()
            self.vault_data["entries"][service] = {
                "username": username,
                "password": password,
                "notes": notes,
                "url": url,
                "category": category,
                "tags": tags or [],
                "created": now,
                "modified": now,
                "history": []
            }
            
            # Save vault
            self.save_vault()
            
            logger.info(f"Added new entry for '{service}'")
            return True
            
        except Exception as e:
            logger.error(f"Error adding entry: {e}")
            return False
    
    def get_entry(self, service: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a password entry from the vault.
        
        Args:
            service: Service name
            
        Returns:
            Optional[Dict[str, Any]]: Entry data or None if not found
        """
        # Check session
        if self.session.is_locked():
            logger.warning("Session is locked")
            return None
            
        self.session.activity()
        
        # Return entry if it exists
        return self.vault_data["entries"].get(service)
    
    def update_entry(self, service: str, username: str = None, password: str = None, 
                    notes: str = None, url: str = None, category: str = None,
                    tags: List[str] = None) -> bool:
        """
        Update an existing password entry.
        
        Args:
            service: Service name
            username: New username (or None to keep current)
            password: New password (or None to keep current)
            notes: New notes (or None to keep current)
            url: New URL (or None to keep current)
            category: New category (or None to keep current)
            tags: New tags (or None to keep current)
            
        Returns:
            bool: True if update was successful
        """
        try:
            # Check session
            if self.session.is_locked():
                logger.warning("Session is locked")
                return False
                
            self.session.activity()
            
            # Check if entry exists
            if service not in self.vault_data["entries"]:
                logger.warning(f"No entry found for '{service}'")
                return False
            
            entry = self.vault_data["entries"][service]
            
            # Update password history if changing password
            if password is not None and password != entry["password"]:
                # Add current password to history
                history = entry.get("history", [])
                history.append({
                    "password": entry["password"],
                    "changed": datetime.now().isoformat()
                })
                
                # Limit history size
                history = history[-self.config["password_history_count"]:]
                entry["history"] = history
            
            # Update entry fields
            if username is not None:
                entry["username"] = username
                
            if password is not None:
                entry["password"] = password
                
            if notes is not None:
                entry["notes"] = notes
                
            if url is not None:
                entry["url"] = url
                
            if category is not None:
                # Validate category
                if category not in self.vault_data["categories"]:
                    # Create new category
                    self.add_category(category)
                entry["category"] = category
                
            if tags is not None:
                entry["tags"] = tags
            
            # Update modification time
            entry["modified"] = datetime.now().isoformat()
            
            # Save vault
            self.save_vault()
            
            logger.info(f"Updated entry for '{service}'")
            return True
            
        except Exception as e:
            logger.error(f"Error updating entry: {e}")
            return False
    
    def delete_entry(self, service: str) -> bool:
        """
        Delete a password entry from the vault.
        
        Args:
            service: Service name
            
        Returns:
            bool: True if deletion was successful
        """
        try:
            # Check session
            if self.session.is_locked():
                logger.warning("Session is locked")
                return False
                
            self.session.activity()
            
            # Check if entry exists
            if service not in self.vault_data["entries"]:
                logger.warning(f"No entry found for '{service}'")
                return False
            
            # Delete entry
            del self.vault_data["entries"][service]
            
            # Save vault
            self.save_vault()
            
            logger.info(f"Deleted entry for '{service}'")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting entry: {e}")
            return False
    
    def find_entries(self, query: str) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Search for entries matching the query.
        
        Args:
            query: Search query
            
        Returns:
            List[Tuple[str, Dict[str, Any]]]: List of matching (service, entry) pairs
        """
        # Check session
        if self.session.is_locked():
            logger.warning("Session is locked")
            return []
            
        self.session.activity()
        
        results = []
        query = query.lower()
        
        for service, entry in self.vault_data["entries"].items():
            # Search in service name
            if query in service.lower():
                results.append((service, entry))
                continue
                
            # Search in username
            if query in entry["username"].lower():
                results.append((service, entry))
                continue
                
            # Search in notes
            if query in entry["notes"].lower():
                results.append((service, entry))
                continue
                
            # Search in URL
            if query in entry["url"].lower():
                results.append((service, entry))
                continue
                
            # Search in tags
            if any(query in tag.lower() for tag in entry.get("tags", [])):
                results.append((service, entry))
                continue
        
        return results
    
    def list_entries(self, category: str = None) -> List[Tuple[str, Dict[str, Any]]]:
        """
        List all entries, optionally filtered by category.
        
        Args:
            category: Category to filter by, or None for all
            
        Returns:
            List[Tuple[str, Dict[str, Any]]]: List of (service, entry) pairs
        """
        # Check session
        if self.session.is_locked():
            logger.warning("Session is locked")
            return []
            
        self.session.activity()
        
        # Filter by category if specified
        if category:
            return [
                (service, entry) 
                for service, entry in self.vault_data["entries"].items()
                if entry.get("category") == category
            ]
        
        # Return all entries
        return list(self.vault_data["entries"].items())
    
    def add_category(self, name: str, description: str = "") -> bool:
        """
        Add a new category.
        
        Args:
            name: Category name
            description: Category description
            
        Returns:
            bool: True if category was added successfully
        """
        try:
            # Check session
            if self.session.is_locked():
                logger.warning("Session is locked")
                return False
                
            self.session.activity()
            
            # Check if category already exists
            if name in self.vault_data["categories"]:
                logger.warning(f"Category '{name}' already exists")
                return False
            
            # Add category
            self.vault_data["categories"][name] = {
                "description": description,
                "created": datetime.now().isoformat()
            }
            
            # Save vault
            self.save_vault()
            
            logger.info(f"Added new category '{name}'")
            return True
            
        except Exception as e:
            logger.error(f"Error adding category: {e}")
            return False
    
    def delete_category(self, name: str, move_to: str = "Uncategorized") -> bool:
        """
        Delete a category and move its entries to another category.
        
        Args:
            name: Category to delete
            move_to: Category to move entries to
            
        Returns:
            bool: True if deletion was successful
        """
        try:
            # Check session
            if self.session.is_locked():
                logger.warning("Session is locked")
                return False
                
            self.session.activity()
            
            # Can't delete Uncategorized
            if name == "Uncategorized":
                logger.warning("Cannot delete the Uncategorized category")
                return False
            
            # Check if category exists
            if name not in self.vault_data["categories"]:
                logger.warning(f"Category '{name}' not found")
                return False
            
            # Check if target category exists
            if move_to not in self.vault_data["categories"]:
                logger.warning(f"Target category '{move_to}' not found")
                return False
            
            # Move entries to target category
            moved_count = 0
            for service, entry in self.vault_data["entries"].items():
                if entry.get("category") == name:
                    entry["category"] = move_to
                    moved_count += 1
            
            # Delete category
            del self.vault_data["categories"][name]
            
            # Save vault
            self.save_vault()
            
            logger.info(f"Deleted category '{name}' and moved {moved_count} entries to '{move_to}'")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting category: {e}")
            return False
    
    def list_categories(self) -> List[Tuple[str, Dict[str, Any]]]:
        """
        List all categories.
        
        Returns:
            List[Tuple[str, Dict[str, Any]]]: List of (name, data) pairs
        """
        # Check session
        if self.session.is_locked():
            logger.warning("Session is locked")
            return []
            
        self.session.activity()
        
        return list(self.vault_data["categories"].items())
    
    def update_config(self, new_config: Dict[str, Any]) -> bool:
        """
        Update vault configuration.
        
        Args:
            new_config: New configuration values
            
        Returns:
            bool: True if update was successful
        """
        try:
            # Update config
            self.config.update(new_config)
            
            # Save config
            self._save_config()
            
            # Update session timeout
            if "timeout_minutes" in new_config:
                self.session.timeout_minutes = new_config["timeout_minutes"]
                self.session.activity()
            
            logger.info("Configuration updated")
            return True
            
        except Exception as e:
            logger.error(f"Error updating configuration: {e}")
            return False