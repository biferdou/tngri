# Tngri Password Manager

A secure, command-line based password vault built with Python.

## Overview

Tngri is a lightweight password manager that securely stores your credentials locally. It provides a simple terminal interface perfect for developers, system administrators, and privacy-conscious users who prefer command-line tools.

## Features

- Strong encryption (AES-256 with PBKDF2)
- Password generation with customizable options
- Organize credentials with categories and tags
- Search functionality
- Auto-clearing clipboard for security
- Session timeout and auto-locking
- Backup and restore capabilities
- Password history tracking

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/biferdou/tngri.git
cd tngri

# Install dependencies
pip install -r requirements.txt

# Make the main script executable
chmod +x tngri.py
```

## Usage

### Running Tngri

```bash
# Run directly
python tngri.py

# Or with options
python tngri.py --vault /custom/path/to/vault.dat --timeout 10
```

### First-time Setup

When you run Tngri for the first time, it will create a new vault and prompt you to set a master password. Choose a strong, memorable password - this is the key to all your other passwords.

### Basic Commands

The main menu provides access to all features:

1. Add password - Store new credentials
2. Get password - Retrieve and view stored credentials
3. Update password - Modify existing entries
4. Delete password - Remove entries from the vault
5. List services - View and filter all stored services
6. Generate password - Create secure random passwords
7. Manage categories - Organize passwords with categories
8. Manage backups - Create, view and restore backups
9. Change master password - Update your vault master password
10. Settings - Configure application behavior
11. Lock vault - Manually lock the vault
12. Exit - Close the application

## Security

- Your vault is encrypted with AES-256
- Master password is never stored, only used for key derivation
- All data remains local on your machine
- Automatic session timeout for security
- Clipboard contents are automatically cleared

## Project Structure

```
tngri/
├── tngri.py                  # Main entry point
├── core/                     # Core functionality
├── utils/                    # Utility modules
├── ui/                       # User interface
└── models/                   # Data models
```

## Development

To set up a development environment:

```bash
# Clone the repository
git clone https://github.com/biferdou/tngri.git
cd tngri

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## License

This project is licensed under the MIT License.
