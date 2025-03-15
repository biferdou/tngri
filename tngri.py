#!/usr/bin/env python3
"""
Tngri Password Manager

A secure, command-line based password vault.
"""

import os
import sys
import logging
import argparse

# Import core modules
from core.vault import TngriVault

# Import UI modules
from ui.menu import display_main_menu
from ui.colors import Colors
from ui.cli import setup_new_vault, get_master_password

# Set up logging
def setup_logging(debug=False):
    """Configure application logging"""
    log_dir = os.path.expanduser("~/.tngri")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    log_level = logging.DEBUG if debug else logging.INFO
    
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(log_dir, "tngri.log")),
            logging.StreamHandler() if debug else logging.NullHandler()
        ]
    )
    return logging.getLogger("tngri")


def display_banner():
    """Display the application banner"""
    print(Colors.CYAN + r"""
 _____                   _   _____ _           _     
|_   _|                 (_) |_   _| |         (_)    
  | | _ __   __ _ _ __   _    | | | |__   ___  _  ___
  | || '_ \ / _` | '_ \ | |   | | | '_ \ / _ \| |/ __|
  | || | | | (_| | | | || |   | | | | | | (_) | | (__ 
  \_/_| |_|\__, |_| |_|/ |   \_/ |_| |_|\___/|_|\___|
            __/ |     |__/                            
           |___/                                      
""" + Colors.RESET)
    print(Colors.BOLD + "Tngri Password Manager" + Colors.RESET)
    print("A secure, command-line based password vault.")
    print("Version 1.0.0")
    print()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Tngri Password Manager")
    parser.add_argument("--vault", help="Path to vault file (default: ~/.tngri/vault.dat)")
    parser.add_argument("--timeout", type=int, default=5, help="Session timeout in minutes (0 to disable)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def check_dependencies():
    """Check for required dependencies"""
    try:
        import cryptography
    except ImportError:
        print(Colors.RED + "Error: cryptography module not found." + Colors.RESET)
        print("Install it with: pip install cryptography")
        return False
        
    try:
        import pyperclip
    except ImportError:
        print(Colors.YELLOW + "Warning: pyperclip module not found. Clipboard functions will be disabled." + Colors.RESET)
        print("Install it with: pip install pyperclip")
    
    return True


def main():
    """Main function for the password manager"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Set up logging
    logger = setup_logging(args.debug)
    
    try:
        # Display banner
        display_banner()
        
        # Check dependencies
        if not check_dependencies():
            sys.exit(1)
        
        # Create vault instance
        vault = TngriVault(args.vault, args.timeout)
        
        # Check if vault exists
        vault_exists = os.path.exists(vault.vault_path) and os.path.exists(vault.salt_path)
        
        if not vault_exists:
            if not setup_new_vault(vault):
                print(Colors.RED + "Failed to set up vault. Exiting." + Colors.RESET)
                sys.exit(1)
        else:
            # Unlock existing vault
            attempts = 0
            while attempts < 3:
                if vault.unlock(get_master_password()):
                    break
                attempts += 1
            
            if attempts == 3:
                print(Colors.RED + "Too many incorrect attempts. Exiting." + Colors.RESET)
                sys.exit(1)
        
        # Start main menu loop
        display_main_menu(vault)
        
    except KeyboardInterrupt:
        print("\n" + Colors.GREEN + "Operation cancelled. Exiting." + Colors.RESET)
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}", exc_info=True)
        print(Colors.RED + f"An error occurred: {e}" + Colors.RESET)
        sys.exit(1)


if __name__ == "__main__":
    main()