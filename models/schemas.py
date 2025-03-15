"""
Data schemas for the Tngri Password Manager.
"""

from datetime import datetime
from typing import Dict, Any, List

# Default vault structure
DEFAULT_VAULT_STRUCTURE = {
    "version": "1.0.0",
    "entries": {},
    "categories": {
        "Uncategorized": {
            "description": "Default category", 
            "created": datetime.now().isoformat()
        }
    },
    "metadata": {
        "created": datetime.now().isoformat(),
        "last_modified": datetime.now().isoformat(),
        "last_accessed": datetime.now().isoformat()
    }
}

# Entry schema for validation
ENTRY_SCHEMA = {
    "username": str,
    "password": str,
    "notes": str,
    "url": str,
    "category": str,
    "tags": list,
    "created": str,
    "modified": str,
    "history": list
}

# Category schema for validation
CATEGORY_SCHEMA = {
    "description": str,
    "created": str
}

# Password history item schema
PASSWORD_HISTORY_SCHEMA = {
    "password": str,
    "changed": str
}

# Configuration schema
CONFIG_SCHEMA = {
    "timeout_minutes": int,
    "clipboard_clear_seconds": int,
    "backup_enabled": bool,
    "backup_count": int,
    "password_history_count": int
}


def create_entry(username: str, password: str, notes: str = "", url: str = "",
                category: str = "Uncategorized", tags: List[str] = None) -> Dict[str, Any]:
    """
    Create a new entry with proper structure.
    
    Args:
        username: Username
        password: Password
        notes: Additional notes
        url: Website URL
        category: Category name
        tags: List of tags
        
    Returns:
        Dict[str, Any]: Structured entry
    """
    now = datetime.now().isoformat()
    return {
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


def create_category(description: str = "") -> Dict[str, Any]:
    """
    Create a new category with proper structure.
    
    Args:
        description: Category description
        
    Returns:
        Dict[str, Any]: Structured category
    """
    return {
        "description": description,
        "created": datetime.now().isoformat()
    }


def create_password_history_item(password: str) -> Dict[str, str]:
    """
    Create a password history item.
    
    Args:
        password: Previous password
        
    Returns:
        Dict[str, str]: Structured history item
    """
    return {
        "password": password,
        "changed": datetime.now().isoformat()
    }


def validate_entry(entry: Dict[str, Any]) -> bool:
    """
    Validate an entry against the schema.
    
    Args:
        entry: Entry to validate
        
    Returns:
        bool: True if entry is valid
    """
    try:
        # Check required fields
        for field, field_type in ENTRY_SCHEMA.items():
            if field not in entry:
                return False
            if not isinstance(entry[field], field_type):
                return False
        return True
    except Exception:
        return False


def validate_category(category: Dict[str, Any]) -> bool:
    """
    Validate a category against the schema.
    
    Args:
        category: Category to validate
        
    Returns:
        bool: True if category is valid
    """
    try:
        # Check required fields
        for field, field_type in CATEGORY_SCHEMA.items():
            if field not in category:
                return False
            if not isinstance(category[field], field_type):
                return False
        return True
    except Exception:
        return False