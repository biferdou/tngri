"""
Command-line interface functions for the Tngri Password Manager.
"""

import getpass
import logging

from core.vault import TngriVault
from ui.colors import Colors, colorize
from utils.password import check_password_strength, generate_password
from utils.clipboard import SecureClipboard

logger = logging.getLogger("tngri.cli")


def get_master_password() -> str:
    """
    Securely get the master password from the user.
    
    Returns:
        str: The entered master password
    """
    while True:
        password = getpass.getpass(colorize("Enter master password: ", Colors.BOLD))
        if len(password) < 8:
            print(colorize("Password must be at least 8 characters long.", Colors.YELLOW))
            continue
        return password


def setup_new_vault(vault: TngriVault) -> bool:
    """
    Set up a new password vault.
    
    Args:
        vault: The vault instance
        
    Returns:
        bool: True if setup was successful
    """
    print(colorize("\nCreating a new password vault...", Colors.BLUE))
    
    while True:
        password = getpass.getpass(colorize("Create master password (min 8 characters): ", Colors.BOLD))
        if len(password) < 8:
            print(colorize("Password must be at least 8 characters long.", Colors.YELLOW))
            continue
        
        # Check password strength
        score, feedback = check_password_strength(password)
        if score < 60:
            print(colorize(f"Warning: {feedback}", Colors.YELLOW))
            confirm = input("Use this password anyway? (y/n): ").lower()
            if confirm != 'y':
                continue
        
        confirm = getpass.getpass(colorize("Confirm master password: ", Colors.BOLD))
        if password != confirm:
            print(colorize("Passwords do not match. Try again.", Colors.RED))
            continue
        
        break
    
    return vault.setup(password)


def add_password(vault: TngriVault) -> None:
    """
    Add a new password to the vault.
    
    Args:
        vault: The vault instance
    """
    print(colorize("\n=== Add Password ===", Colors.BLUE))
    
    service = input(colorize("Service name: ", Colors.BOLD))
    if not service:
        print(colorize("Service name cannot be empty.", Colors.YELLOW))
        return
    
    username = input(colorize("Username: ", Colors.BOLD))
    
    url = input(colorize("URL (optional): ", Colors.BOLD))
    
    # Category selection
    categories = [name for name, _ in vault.list_categories()]
    if categories:
        print(colorize("Categories:", Colors.BOLD))
        for i, name in enumerate(categories, 1):
            print(f"{i}. {name}")
        
        cat_choice = input(colorize("Select category (number or name, default: Uncategorized): ", Colors.BOLD))
        try:
            if cat_choice.isdigit() and 1 <= int(cat_choice) <= len(categories):
                category = categories[int(cat_choice) - 1]
            elif cat_choice in categories:
                category = cat_choice
            elif cat_choice:
                # Create new category
                category = cat_choice
                vault.add_category(category)
            else:
                category = "Uncategorized"
        except (ValueError, IndexError):
            category = "Uncategorized"
    else:
        category = "Uncategorized"
    
    # Tags
    tags_input = input(colorize("Tags (comma-separated, optional): ", Colors.BOLD))
    tags = [tag.strip() for tag in tags_input.split(",")] if tags_input else []
    
    # Password generation or manual entry
    use_generated = input(colorize("Generate a secure password? (y/n): ", Colors.BOLD)).lower() == 'y'
    if use_generated:
        try:
            length = int(input(colorize("Password length (default: 16): ", Colors.BOLD) or "16"))
        except ValueError:
            length = 16
        
        use_symbols = input(colorize("Include symbols? (y/n, default: y): ", Colors.BOLD)).lower() != 'n'
        use_uppercase = input(colorize("Include uppercase letters? (y/n, default: y): ", Colors.BOLD)).lower() != 'n'
        use_digits = input(colorize("Include digits? (y/n, default: y): ", Colors.BOLD)).lower() != 'n'
        
        password = generate_password(length, use_symbols, use_uppercase, use_digits)
        print(colorize(f"Generated password: {password}", Colors.GREEN))
        
        # Offer to copy to clipboard
        if input(colorize("Copy to clipboard? (y/n): ", Colors.BOLD)).lower() == 'y':
            try:
                SecureClipboard.copy(password, vault.config["clipboard_clear_seconds"])
                print(colorize(f"Password copied to clipboard! Will clear in {vault.config['clipboard_clear_seconds']} seconds.", Colors.GREEN))
            except Exception as e:
                print(colorize(f"Could not copy to clipboard: {e}", Colors.YELLOW))
    else:
        password = getpass.getpass(colorize("Password: ", Colors.BOLD))
        if not password:
            print(colorize("Password cannot be empty.", Colors.YELLOW))
            return
    
    notes = input(colorize("Notes (optional): ", Colors.BOLD))
    
    if vault.add_entry(service, username, password, notes, url, category, tags):
        print(colorize(f"Entry for '{service}' added successfully!", Colors.GREEN))
    else:
        print(colorize("Failed to add entry.", Colors.RED))


def get_password(vault: TngriVault) -> None:
    """
    Retrieve a password from the vault.
    
    Args:
        vault: The vault instance
    """
    print(colorize("\n=== Get Password ===", Colors.BLUE))
    
    # Get service name or list entries
    service = input(colorize("Service name (or 'list' to see all): ", Colors.BOLD))
    if service.lower() == 'list':
        list_services(vault)
        service = input(colorize("Service name: ", Colors.BOLD))
    
    entry = vault.get_entry(service)
    
    if not entry:
        print(colorize(f"No entry found for '{service}'", Colors.YELLOW))
        
        # Check for similar entries
        similar = vault.find_entries(service)
        if similar:
            print(colorize("\nDid you mean:", Colors.YELLOW))
            for s, _ in similar[:5]:
                print(f"- {s}")
        return
    
    # Display entry details
    print(colorize(f"\nService: {service}", Colors.GREEN))
    print(f"Username: {entry['username']}")
    print(f"Password: {'*' * len(entry['password'])}")
    if entry.get('url'):
        print(f"URL: {entry['url']}")
    if entry.get('category'):
        print(f"Category: {entry['category']}")
    if entry.get('tags'):
        print(f"Tags: {', '.join(entry['tags'])}")
    if entry.get('notes'):
        print(f"Notes: {entry['notes']}")
    if entry.get('created'):
        print(f"Created: {entry['created']}")
    if entry.get('modified'):
        print(f"Last modified: {entry['modified']}")
    
    # Offer actions
    print(colorize("\nActions:", Colors.BLUE))
    print("1. Copy username to clipboard")
    print("2. Copy password to clipboard")
    print("3. Show password")
    print("4. Copy URL to clipboard")
    print("5. Edit entry")
    print("6. Return to main menu")
    
    choice = input(colorize("\nEnter your choice (1-6): ", Colors.BOLD))
    
    try:
        if choice == '1':
            if SecureClipboard.copy(entry['username'], vault.config["clipboard_clear_seconds"]):
                print(colorize(f"Username copied to clipboard! Will clear in {vault.config['clipboard_clear_seconds']} seconds.", Colors.GREEN))
        elif choice == '2':
            if SecureClipboard.copy(entry['password'], vault.config["clipboard_clear_seconds"]):
                print(colorize(f"Password copied to clipboard! Will clear in {vault.config['clipboard_clear_seconds']} seconds.", Colors.GREEN))
        elif choice == '3':
            print(colorize(f"Password: {entry['password']}", Colors.GREEN))
        elif choice == '4':
            if entry.get('url'):
                if SecureClipboard.copy(entry['url'], vault.config["clipboard_clear_seconds"]):
                    print(colorize(f"URL copied to clipboard! Will clear in {vault.config['clipboard_clear_seconds']} seconds.", Colors.GREEN))
            else:
                print(colorize("No URL available for this entry.", Colors.YELLOW))
        elif choice == '5':
            update_password(vault, service)
    except Exception as e:
        print(colorize(f"Error: {e}", Colors.YELLOW))


def update_password(vault: TngriVault, service: str = None) -> None:
    """
    Update an existing password entry.
    
    Args:
        vault: The vault instance
        service: Optional service name to update
    """
    print(colorize("\n=== Update Password ===", Colors.BLUE))
    
    if service is None:
        service = input(colorize("Service name (or 'list' to see all): ", Colors.BOLD))
        if service.lower() == 'list':
            list_services(vault)
            service = input(colorize("Service name: ", Colors.BOLD))
    
    if service not in vault.vault_data["entries"]:
        print(colorize(f"No entry found for '{service}'", Colors.YELLOW))
        return
    
    current = vault.get_entry(service)
    
    print(colorize(f"\nUpdating entry for '{service}':", Colors.GREEN))
    print(f"Current username: {current['username']}")
    username = input(colorize("New username (leave empty to keep current): ", Colors.BOLD))
    username = username if username else None
    
    print(f"Current URL: {current.get('url', '')}")
    url = input(colorize("New URL (leave empty to keep current): ", Colors.BOLD))
    url = url if url else None
    
    # Category selection
    print(f"Current category: {current.get('category', 'Uncategorized')}")
    categories = [name for name, _ in vault.list_categories()]
    if categories:
        print(colorize("Categories:", Colors.BOLD))
        for i, name in enumerate(categories, 1):
            print(f"{i}. {name}")
        
        cat_choice = input(colorize("Select new category (number or name, leave empty to keep current): ", Colors.BOLD))
        try:
            if cat_choice.isdigit() and 1 <= int(cat_choice) <= len(categories):
                category = categories[int(cat_choice) - 1]
            elif cat_choice in categories:
                category = cat_choice
            elif cat_choice:
                # Create new category
                category = cat_choice
                vault.add_category(category)
            else:
                category = None
        except (ValueError, IndexError):
            category = None
    else:
        category = None
    
    # Tags
    current_tags = current.get('tags', [])
    print(f"Current tags: {', '.join(current_tags) if current_tags else 'None'}")
    tags_input = input(colorize("New tags (comma-separated, leave empty to keep current): ", Colors.BOLD))
    tags = [tag.strip() for tag in tags_input.split(",")] if tags_input else None
    
    # Password update
    pass_choice = input(colorize("Update password? (g=generate, m=manual, empty=keep current): ", Colors.BOLD)).lower()
    
    if pass_choice == 'g':
        try:
            length = int(input(colorize("Password length (default: 16): ", Colors.BOLD) or "16"))
        except ValueError:
            length = 16
        
        use_symbols = input(colorize("Include symbols? (y/n, default: y): ", Colors.BOLD)).lower() != 'n'
        use_uppercase = input(colorize("Include uppercase letters? (y/n, default: y): ", Colors.BOLD)).lower() != 'n'
        use_digits = input(colorize("Include digits? (y/n, default: y): ", Colors.BOLD)).lower() != 'n'
        
        password = generate_password(length, use_symbols, use_uppercase, use_digits)
        print(colorize(f"Generated password: {password}", Colors.GREEN))
        
        # Offer to copy to clipboard
        if input(colorize("Copy to clipboard? (y/n): ", Colors.BOLD)).lower() == 'y':
            try:
                SecureClipboard.copy(password, vault.config["clipboard_clear_seconds"])
                print(colorize(f"Password copied to clipboard! Will clear in {vault.config['clipboard_clear_seconds']} seconds.", Colors.GREEN))
            except Exception as e:
                print(colorize(f"Could not copy to clipboard: {e}", Colors.YELLOW))
    elif pass_choice == 'm':
        password = getpass.getpass(colorize("New password: ", Colors.BOLD))
    else:
        password = None
    
    print(f"Current notes: {current['notes']}")
    notes = input(colorize("New notes (leave empty to keep current): ", Colors.BOLD))
    notes = notes if notes else None
    
    if vault.update_entry(service, username, password, notes, url, category, tags):
        print(colorize(f"Entry for '{service}' updated successfully!", Colors.GREEN))
    else:
        print(colorize(f"Failed to update entry for '{service}'", Colors.RED))


def delete_password(vault: TngriVault) -> None:
    """
    Delete a password entry.
    
    Args:
        vault: The vault instance
    """
    print(colorize("\n=== Delete Password ===", Colors.BLUE))
    
    service = input(colorize("Service name (or 'list' to see all): ", Colors.BOLD))
    if service.lower() == 'list':
        list_services(vault)
        service = input(colorize("Service name: ", Colors.BOLD))
    
    if service not in vault.vault_data["entries"]:
        print(colorize(f"No entry found for '{service}'", Colors.YELLOW))
        return
    
    confirm = input(colorize(f"Are you sure you want to delete the entry for '{service}'? (y/n): ", Colors.BOLD)).lower()
    
    if confirm == 'y':
        if vault.delete_entry(service):
            print(colorize(f"Entry for '{service}' deleted successfully!", Colors.GREEN))
        else:
            print(colorize(f"Failed to delete entry for '{service}'", Colors.RED))


def list_services(vault: TngriVault) -> None:
    """
    List all services in the vault.
    
    Args:
        vault: The vault instance
    """
    print(colorize("\n=== Services ===", Colors.BLUE))
    
    # Get filtering options
    filter_choice = input(colorize("Filter by (1=All, 2=Category, 3=Search): ", Colors.BOLD) or "1")
    
    if filter_choice == "2":
        # List by category
        categories = [name for name, _ in vault.list_categories()]
        if not categories:
            print(colorize("No categories found.", Colors.YELLOW))
            return
            
        print(colorize("Categories:", Colors.BOLD))
        for i, name in enumerate(categories, 1):
            print(f"{i}. {name}")
            
        cat_choice = input(colorize("Select category (number or name): ", Colors.BOLD))
        try:
            if cat_choice.isdigit() and 1 <= int(cat_choice) <= len(categories):
                category = categories[int(cat_choice) - 1]
            elif cat_choice in categories:
                category = cat_choice
            else:
                print(colorize("Invalid category. Showing all entries.", Colors.YELLOW))
                category = None
        except (ValueError, IndexError):
            print(colorize("Invalid choice. Showing all entries.", Colors.YELLOW))
            category = None
            
        entries = vault.list_entries(category)
    elif filter_choice == "3":
        # Search
        query = input(colorize("Search query: ", Colors.BOLD))
        entries = vault.find_entries(query)
        print(colorize(f"Found {len(entries)} matching entries", Colors.GREEN))
    else:
        # All entries
        entries = vault.list_entries()
    
    # Sort options
    print(colorize("\nSort by:", Colors.BOLD))
    print("1. Service name (A-Z)")
    print("2. Service name (Z-A)")
    print("3. Last modified (newest first)")
    print("4. Last modified (oldest first)")
    print("5. Category")
    
    sort_choice = input(colorize("Select sorting (1-5, default: 1): ", Colors.BOLD) or "1")
    
    if sort_choice == "2":
        entries.sort(key=lambda x: x[0], reverse=True)
    elif sort_choice == "3":
        entries.sort(key=lambda x: x[1].get("modified", ""), reverse=True)
    elif sort_choice == "4":
        entries.sort(key=lambda x: x[1].get("modified", ""))
    elif sort_choice == "5":
        entries.sort(key=lambda x: x[1].get("category", "Uncategorized"))
    else:
        entries.sort(key=lambda x: x[0])
    
    if not entries:
        print(colorize("No entries found.", Colors.YELLOW))
        return
    
    # Display entries as a table
    print("\n" + colorize(f"{'Service':<25} {'Username':<25} {'Category':<15} {'Last Modified':<20}", Colors.BOLD))
    print("-" * 85)
    
    for service, entry in entries:
        username = entry["username"]
        category = entry.get("category", "Uncategorized")
        modified = entry.get("modified", "")
        if modified:
            try:
                # Format date for display (just date part)
                modified = modified.split("T")[0]
            except:
                pass
                
        print(f"{service:<25} {username:<25} {category:<15} {modified:<20}")
    
    print("\n" + colorize(f"Total entries: {len(entries)}", Colors.GREEN))


def generate_password_cli(vault: TngriVault) -> None:
    """
    Generate a secure random password.
    
    Args:
        vault: The vault instance
    """
    print(colorize("\n=== Generate Password ===", Colors.BLUE))
    
    try:
        length = int(input(colorize("Password length (default: 16): ", Colors.BOLD) or "16"))
    except ValueError:
        length = 16
    
    use_symbols = input(colorize("Include symbols? (y/n, default: y): ", Colors.BOLD)).lower() != 'n'
    use_uppercase = input(colorize("Include uppercase letters? (y/n, default: y): ", Colors.BOLD)).lower() != 'n'
    use_digits = input(colorize("Include digits? (y/n, default: y): ", Colors.BOLD)).lower() != 'n'
    
    password = generate_password(length, use_symbols, use_uppercase, use_digits)
    print(colorize(f"\nGenerated password: {password}", Colors.GREEN))
    
    # Display strength
    score, feedback = check_password_strength(password)
    strength = "Weak" if score < 40 else "Moderate" if score < 60 else "Good" if score < 80 else "Strong"
    print(f"Password strength: {strength} ({score}/100)")
    
    # Offer to copy to clipboard
    if input(colorize("Copy to clipboard? (y/n): ", Colors.BOLD)).lower() == 'y':
        try:
            SecureClipboard.copy(password, vault.config["clipboard_clear_seconds"])
            print(colorize(f"Password copied to clipboard! Will clear in {vault.config['clipboard_clear_seconds']} seconds.", Colors.GREEN))
        except Exception as e:
            print(colorize(f"Could not copy to clipboard: {e}", Colors.YELLOW))
    
    # Offer to save
    if input(colorize("Save this password? (y/n): ", Colors.BOLD)).lower() == 'y':
        add_password(vault)


def change_master_password(vault: TngriVault) -> None:
    """
    Change the master password for the vault.
    
    Args:
        vault: The vault instance
    """
    print(colorize("\n=== Change Master Password ===", Colors.BLUE))
    
    current = getpass.getpass(colorize("Current master password: ", Colors.BOLD))
    
    while True:
        new_password = getpass.getpass(colorize("New master password (min 8 characters): ", Colors.BOLD))
        if len(new_password) < 8:
            print(colorize("Password must be at least 8 characters long.", Colors.YELLOW))
            continue
        
        # Check password strength
        score, feedback = check_password_strength(new_password)
        if score < 60:
            print(colorize(f"Warning: {feedback}", Colors.YELLOW))
            confirm = input("Use this password anyway? (y/n): ").lower()
            if confirm != 'y':
                continue
        
        confirm = getpass.getpass(colorize("Confirm new master password: ", Colors.BOLD))
        if new_password != confirm:
            print(colorize("Passwords do not match. Try again.", Colors.RED))
            continue
        
        break
    
    # Implementation of the change would be added here
    print(colorize("Master password change functionality to be implemented.", Colors.YELLOW))