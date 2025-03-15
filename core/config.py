"""
Configuration management for the Tngri Password Manager.
"""

import os
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("tngri.config")

# Default configuration values
DEFAULT_CONFIG = {
    "timeout_minutes": 5,
    "clipboard_clear_seconds": 30,
    "backup_enabled": True,
    "backup_count": 5,
    "password_history_count": 3,
    "debug_mode": False,
    "auto_lock_on_exit": True,
    "theme": "default"
}


def get_config_path(custom_path: Optional[str] = None) -> str:
    """
    Get the path to the configuration file.
    
    Args:
        custom_path: Optional custom configuration path
        
    Returns:
        str: Path to the configuration file
    """
    if custom_path:
        return custom_path
    
    config_dir = os.path.expanduser("~/.tngri")
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
    
    return os.path.join(config_dir, "config.json")


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from file or create default if not exists.
    
    Args:
        config_path: Optional path to the configuration file
        
    Returns:
        Dict[str, Any]: Configuration dictionary
    """
    path = get_config_path(config_path)
    
    # Create default config if file doesn't exist
    if not os.path.exists(path):
        logger.info("Creating default configuration")
        save_config(DEFAULT_CONFIG, path)
        return DEFAULT_CONFIG.copy()
    
    try:
        with open(path, 'r') as config_file:
            config = json.load(config_file)
            
        # Ensure all default keys exist (for backward compatibility)
        for key, value in DEFAULT_CONFIG.items():
            if key not in config:
                config[key] = value
                
        logger.debug("Configuration loaded successfully")
        return config
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        logger.info("Falling back to default configuration")
        return DEFAULT_CONFIG.copy()


def save_config(config: Dict[str, Any], config_path: Optional[str] = None) -> bool:
    """
    Save configuration to file.
    
    Args:
        config: Configuration dictionary
        config_path: Optional path to the configuration file
        
    Returns:
        bool: True if config was saved successfully
    """
    path = get_config_path(config_path)
    
    try:
        with open(path, 'w') as config_file:
            json.dump(config, config_file, indent=2)
        logger.debug("Configuration saved successfully")
        return True
    except Exception as e:
        logger.error(f"Error saving configuration: {e}")
        return False


def update_config(updates: Dict[str, Any], config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Update specific configuration values.
    
    Args:
        updates: Dictionary of configuration updates
        config_path: Optional path to the configuration file
        
    Returns:
        Dict[str, Any]: Updated configuration dictionary
    """
    config = load_config(config_path)
    config.update(updates)
    save_config(config, config_path)
    return config


def get_config_value(key: str, default: Any = None, config_path: Optional[str] = None) -> Any:
    """
    Get a specific configuration value.
    
    Args:
        key: Configuration key
        default: Default value if key doesn't exist
        config_path: Optional path to the configuration file
        
    Returns:
        Any: Configuration value
    """
    config = load_config(config_path)
    return config.get(key, default)


def set_config_value(key: str, value: Any, config_path: Optional[str] = None) -> bool:
    """
    Set a specific configuration value.
    
    Args:
        key: Configuration key
        value: Configuration value
        config_path: Optional path to the configuration file
        
    Returns:
        bool: True if value was set successfully
    """
    config = load_config(config_path)
    config[key] = value
    return save_config(config, config_path)


def reset_config(config_path: Optional[str] = None) -> bool:
    """
    Reset configuration to defaults.
    
    Args:
        config_path: Optional path to the configuration file
        
    Returns:
        bool: True if config was reset successfully
    """
    return save_config(DEFAULT_CONFIG.copy(), config_path)