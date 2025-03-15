"""
Menu handling for the Tngri Password Manager.
"""

import os
import logging

from core.vault import TngriVault
from ui.colors import Colors, colorize
from ui.cli import (
    add_password, get_password, update_password,
    delete_password, list_services, generate_password_cli,
    change_master_password, get_master_password
)
from utils.clipboard import SecureClipboard

logger = logging.getLogger("tngri.menu")


def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def pause() -> None:
    """Pause execution until user presses Enter."""
    input(colorize("\nPress Enter to continue...", Colors.BOLD))


def display_main_menu(vault: TngriVault) -> None:
    """
    Display the main menu and handle user input.
    
    Args:
        vault: The TngriVault instance
    """
    while True:
        try:
            if vault.session.is_locked():
                print(colorize("\nVault is locked.", Colors.YELLOW))
                if vault.unlock(get_master_password()):
                    continue
                else:
                    print(colorize("Failed to unlock vault. Exiting.", Colors.RED))
                    break
            
            clear_screen()
            print(colorize("\nTngri Password Manager", Colors.BLUE + Colors.BOLD))
            print("1. Add password")
            print("2. Get password")
            print("3. Update password")
            print("4. Delete password")
            print("5. List services")
            print("6. Generate password")
            print("7. Manage categories")
            print("8. Manage backups")
            print("9. Change master password")
            print("10. Settings")
            print("11. Lock vault")
            print("12. Exit")
            
            choice = input(colorize("\nEnter your choice (1-12): ", Colors.BOLD))
            
            if choice == '1':
                add_password(vault)
                pause()
            elif choice == '2':
                get_password(vault)
                pause()
            elif choice == '3':
                update_password(vault)
                pause()
            elif choice == '4':
                delete_password(vault)
                pause()
            elif choice == '5':
                list_services(vault)
                pause()
            elif choice == '6':
                generate_password_cli(vault)
                pause()
            elif choice == '7':
                manage_categories_menu(vault)
            elif choice == '8':
                manage_backups_menu(vault)
            elif choice == '9':
                change_master_password(vault)
                pause()
            elif choice == '10':
                settings_menu(vault)
            elif choice == '11':
                vault.session.lock()
                print(colorize("Vault locked.", Colors.GREEN))
                pause()
            elif choice == '12':
                print(colorize("Goodbye!", Colors.GREEN))
                break
            else:
                print(colorize("Invalid choice. Please try again.", Colors.YELLOW))
                pause()
                
        except KeyboardInterrupt:
            print(colorize("\nOperation cancelled.", Colors.YELLOW))
            confirm_exit = input(colorize("Exit application? (y/n): ", Colors.BOLD)).lower()
            if confirm_exit == 'y':
                print(colorize("Goodbye!", Colors.GREEN))
                break
        except Exception as e:
            logger.error(f"Error in main menu: {e}", exc_info=True)
            print(colorize(f"An error occurred: {e}", Colors.RED))
            pause()
    
    # Clean up before exiting
    try:
        # Clear clipboard if necessary
        SecureClipboard.clear()
        
        # Cancel any timers
        if hasattr(vault, 'session'):
            vault.session.cancel_timers()
    except:
        pass


def manage_categories_menu(vault: TngriVault) -> None:
    """
    Display the category management menu and handle user input.
    
    Args:
        vault: The TngriVault instance
    """
    while True:
        clear_screen()
        print(colorize("\n=== Manage Categories ===", Colors.BLUE))
        print("1. List categories")
        print("2. Add category")
        print("3. Delete category")
        print("4. Return to main menu")
        
        choice = input(colorize("\nEnter your choice (1-4): ", Colors.BOLD))
        
        if choice == '1':
            list_categories(vault)
            pause()
        elif choice == '2':
            add_category(vault)
            pause()
        elif choice == '3':
            delete_category(vault)
            pause()
        elif choice == '4':
            break
        else:
            print(colorize("Invalid choice. Please try again.", Colors.YELLOW))
            pause()


def list_categories(vault: TngriVault) -> None:
    """
    List all categories in the vault.
    
    Args:
        vault: The TngriVault instance
    """
    categories = vault.list_categories()
    if not categories:
        print(colorize("No categories found.", Colors.YELLOW))
        return
        
    print("\n" + colorize(f"{'Category':<20} {'Description':<40} {'Created':<20}", Colors.BOLD))
    print("-" * 80)
    
    for name, data in categories:
        desc = data.get("description", "")
        created = data.get("created", "")
        if created:
            try:
                # Format date for display (just date part)
                created = created.split("T")[0]
            except:
                pass
                
        print(f"{name:<20} {desc:<40} {created:<20}")
        
    # Count entries per category
    entries = vault.list_entries()
    category_counts = {}
    for _, entry in entries:
        category = entry.get("category", "Uncategorized")
        category_counts[category] = category_counts.get(category, 0) + 1
        
    print("\n" + colorize("Entry counts per category:", Colors.BOLD))
    for name, count in category_counts.items():
        print(f"{name}: {count} entries")


def add_category(vault: TngriVault) -> None:
    """
    Add a new category to the vault.
    
    Args:
        vault: The TngriVault instance
    """
    name = input(colorize("Category name: ", Colors.BOLD))
    if not name:
        print(colorize("Category name cannot be empty.", Colors.YELLOW))
        return
        
    description = input(colorize("Description (optional): ", Colors.BOLD))
    
    if vault.add_category(name, description):
        print(colorize(f"Category '{name}' added successfully!", Colors.GREEN))
    else:
        print(colorize(f"Failed to add category '{name}'.", Colors.RED))


def delete_category(vault: TngriVault) -> None:
    """
    Delete a category from the vault.
    
    Args:
        vault: The TngriVault instance
    """
    categories = [name for name, _ in vault.list_categories()]
    if not categories:
        print(colorize("No categories found.", Colors.YELLOW))
        return
        
    print(colorize("Categories:", Colors.BOLD))
    for i, name in enumerate(categories, 1):
        print(f"{i}. {name}")
        
    cat_choice = input(colorize("Select category to delete (number or name): ", Colors.BOLD))
    try:
        if cat_choice.isdigit() and 1 <= int(cat_choice) <= len(categories):
            category = categories[int(cat_choice) - 1]
        elif cat_choice in categories:
            category = cat_choice
        else:
            print(colorize("Invalid category.", Colors.YELLOW))
            return
    except (ValueError, IndexError):
        print(colorize("Invalid choice.", Colors.YELLOW))
        return
        
    if category == "Uncategorized":
        print(colorize("Cannot delete the Uncategorized category.", Colors.YELLOW))
        return
        
    # Get target category
    print(colorize("Move entries to:", Colors.BOLD))
    for i, name in enumerate(categories, 1):
        if name != category:
            print(f"{i}. {name}")
            
    move_choice = input(colorize("Select target category (number or name, default: Uncategorized): ", Colors.BOLD) or "Uncategorized")
    try:
        if move_choice.isdigit() and 1 <= int(move_choice) <= len(categories):
            move_to = categories[int(move_choice) - 1]
        elif move_choice in categories:
            move_to = move_choice
        else:
            move_to = "Uncategorized"
    except (ValueError, IndexError):
        move_to = "Uncategorized"
        
    if vault.delete_category(category, move_to):
        print(colorize(f"Category '{category}' deleted successfully!", Colors.GREEN))
    else:
        print(colorize(f"Failed to delete category '{category}'.", Colors.RED))


def manage_backups_menu(vault: TngriVault) -> None:
    """
    Display the backup management menu and handle user input.
    
    Args:
        vault: The TngriVault instance
    """
    while True:
        clear_screen()
        print(colorize("\n=== Manage Backups ===", Colors.BLUE))
        print("1. List backups")
        print("2. Create backup")
        print("3. Restore from backup")
        print("4. Export vault")
        print("5. Import vault")
        print("6. Return to main menu")
        
        choice = input(colorize("\nEnter your choice (1-6): ", Colors.BOLD))
        
        if choice == '1':
            list_backups(vault)
            pause()
        elif choice == '2':
            create_backup(vault)
            pause()
        elif choice == '3':
            restore_backup(vault)
            pause()
        elif choice == '4':
            export_vault(vault)
            pause()
        elif choice == '5':
            import_vault(vault)
            pause()
        elif choice == '6':
            break
        else:
            print(colorize("Invalid choice. Please try again.", Colors.YELLOW))
            pause()


def list_backups(vault: TngriVault) -> None:
    """
    List available backups.
    
    Args:
        vault: The TngriVault instance
    """
    # This is a placeholder - the actual implementation would need to be added
    print(colorize("Backup listing functionality to be implemented.", Colors.YELLOW))


def create_backup(vault: TngriVault) -> None:
    """
    Create a new backup.
    
    Args:
        vault: The TngriVault instance
    """
    # This is a placeholder - the actual implementation would need to be added
    print(colorize("Backup creation functionality to be implemented.", Colors.YELLOW))


def restore_backup(vault: TngriVault) -> None:
    """
    Restore from a backup.
    
    Args:
        vault: The TngriVault instance
    """
    # This is a placeholder - the actual implementation would need to be added
    print(colorize("Backup restoration functionality to be implemented.", Colors.YELLOW))


def export_vault(vault: TngriVault) -> None:
    """
    Export the vault to a file.
    
    Args:
        vault: The TngriVault instance
    """
    # This is a placeholder - the actual implementation would need to be added
    print(colorize("Vault export functionality to be implemented.", Colors.YELLOW))


def import_vault(vault: TngriVault) -> None:
    """
    Import a vault from a file.
    
    Args:
        vault: The TngriVault instance
    """
    # This is a placeholder - the actual implementation would need to be added
    print(colorize("Vault import functionality to be implemented.", Colors.YELLOW))


def settings_menu(vault: TngriVault) -> None:
    """
    Display the settings menu and handle user input.
    
    Args:
        vault: The TngriVault instance
    """
    while True:
        clear_screen()
        print(colorize("\n=== Settings ===", Colors.BLUE))
        
        print(colorize("Current settings:", Colors.BOLD))
        for key, value in vault.config.items():
            print(f"{key}: {value}")
        
        print("\nWhat would you like to change?")
        print("1. Session timeout")
        print("2. Clipboard clear time")
        print("3. Backup settings")
        print("4. Password history")
        print("5. Return to main menu")
        
        choice = input(colorize("\nEnter your choice (1-5): ", Colors.BOLD))
        
        if choice == '1':
            change_timeout_setting(vault)
            pause()
        elif choice == '2':
            change_clipboard_setting(vault)
            pause()
        elif choice == '3':
            change_backup_settings(vault)
            pause()
        elif choice == '4':
            change_history_settings(vault)
            pause()
        elif choice == '5':
            break
        else:
            print(colorize("Invalid choice. Please try again.", Colors.YELLOW))
            pause()


def change_timeout_setting(vault: TngriVault) -> None:
    """
    Change the session timeout setting.
    
    Args:
        vault: The TngriVault instance
    """
    try:
        timeout = int(input(colorize(f"Session timeout in minutes (current: {vault.config['timeout_minutes']}, 0 to disable): ", Colors.BOLD)))
        new_config = {"timeout_minutes": timeout}
        
        if vault.update_config(new_config):
            print(colorize("Session timeout updated successfully!", Colors.GREEN))
        else:
            print(colorize("Failed to update session timeout.", Colors.RED))
    except ValueError:
        print(colorize("Invalid input. Please enter a number.", Colors.YELLOW))


def change_clipboard_setting(vault: TngriVault) -> None:
    """
    Change the clipboard clear time setting.
    
    Args:
        vault: The TngriVault instance
    """
    try:
        clear_time = int(input(colorize(f"Clipboard clear time in seconds (current: {vault.config['clipboard_clear_seconds']}, 0 to disable): ", Colors.BOLD)))
        new_config = {"clipboard_clear_seconds": clear_time}
        
        if vault.update_config(new_config):
            print(colorize("Clipboard clear time updated successfully!", Colors.GREEN))
        else:
            print(colorize("Failed to update clipboard clear time.", Colors.RED))
    except ValueError:
        print(colorize("Invalid input. Please enter a number.", Colors.YELLOW))


def change_backup_settings(vault: TngriVault) -> None:
    """
    Change backup settings.
    
    Args:
        vault: The TngriVault instance
    """
    enabled = input(colorize(f"Enable automatic backups? (y/n, current: {vault.config['backup_enabled']}): ", Colors.BOLD)).lower()
    if enabled in ('y', 'n'):
        new_config = {"backup_enabled": (enabled == 'y')}
        
        try:
            count = int(input(colorize(f"Number of backups to keep (current: {vault.config['backup_count']}): ", Colors.BOLD)))
            if count > 0:
                new_config["backup_count"] = count
        except ValueError:
            print(colorize("Invalid input. Please enter a number.", Colors.YELLOW))
        
        if vault.update_config(new_config):
            print(colorize("Backup settings updated successfully!", Colors.GREEN))
        else:
            print(colorize("Failed to update backup settings.", Colors.RED))


def change_history_settings(vault: TngriVault) -> None:
    """
    Change password history settings.
    
    Args:
        vault: The TngriVault instance
    """
    try:
        count = int(input(colorize(f"Number of password history entries to keep (current: {vault.config['password_history_count']}): ", Colors.BOLD)))
        if count >= 0:
            new_config = {"password_history_count": count}
            
            if vault.update_config(new_config):
                print(colorize("Password history settings updated successfully!", Colors.GREEN))
            else:
                print(colorize("Failed to update password history settings.", Colors.RED))
        else:
            print(colorize("Please enter a non-negative number.", Colors.YELLOW))
    except ValueError:
        print(colorize("Invalid input. Please enter a number.", Colors.YELLOW))