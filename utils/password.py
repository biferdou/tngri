"""
Password generation and strength evaluation utilities.
"""

import string
import secrets
import logging
from typing import Tuple, List

logger = logging.getLogger("tngri.password")


def generate_password(length: int = 16, use_symbols: bool = True,
                     use_uppercase: bool = True, use_digits: bool = True) -> str:
    """
    Generate a secure random password.
    
    Args:
        length: Password length
        use_symbols: Include special characters/symbols
        use_uppercase: Include uppercase letters
        use_digits: Include digits
        
    Returns:
        str: Generated password
    """
    # Ensure minimum length
    if length < 8:
        length = 8
        logger.warning("Password length adjusted to minimum of 8 characters")
        
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase if use_uppercase else ""
    digits = string.digits if use_digits else ""
    symbols = string.punctuation if use_symbols else ""
    
    # Ensure we have at least lowercase letters
    if not (use_uppercase or use_digits or use_symbols):
        # Generate password with only lowercase
        return ''.join(secrets.choice(lowercase) for _ in range(length))
    
    # Initialize with required character types
    pwd = []
    
    # Add one of each required character type
    pwd.append(secrets.choice(lowercase))
    
    if use_uppercase:
        pwd.append(secrets.choice(uppercase))
        
    if use_digits:
        pwd.append(secrets.choice(digits))
        
    if use_symbols:
        pwd.append(secrets.choice(symbols))
        
    # Fill the rest with random characters from all sets
    all_chars = lowercase + uppercase + digits + symbols
    pwd.extend(secrets.choice(all_chars) for _ in range(length - len(pwd)))
    
    # Shuffle the password characters
    secrets.SystemRandom().shuffle(pwd)
    return ''.join(pwd)


def check_password_strength(password: str) -> Tuple[int, str]:
    """
    Check password strength and provide feedback.
    
    Args:
        password: The password to check
        
    Returns:
        Tuple of (score, feedback) where score is 0-100
    """
    score = 0
    feedback = []
    
    # Length
    if len(password) < 8:
        feedback.append("Password is too short (minimum 8 characters)")
    elif len(password) >= 12:
        score += 25
    else:
        score += 10
        
    # Character classes
    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    character_score = (has_lowercase + has_uppercase + has_digit + has_special) * 15
    score += character_score
    
    if not has_lowercase:
        feedback.append("Add lowercase letters")
    if not has_uppercase:
        feedback.append("Add uppercase letters")
    if not has_digit:
        feedback.append("Add numbers")
    if not has_special:
        feedback.append("Add special characters")
        
    # Entropy
    charset_size = 0
    if has_lowercase:
        charset_size += 26
    if has_uppercase:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += len(string.punctuation)
        
    if charset_size > 0:
        entropy = len(password) * (charset_size.bit_length())
        if entropy > 60:
            score += 20
        elif entropy > 40:
            score += 10
        
    # Repeating characters
    repeated_chars = len(password) - len(set(password))
    if repeated_chars > 0:
        score -= min(repeated_chars * 5, 20)
        if repeated_chars > 2:
            feedback.append("Avoid repeated characters")
    
    # Common patterns
    common_patterns = [
        "123", "abc", "qwerty", "password", "admin", "welcome",
        "letmein", "monkey", "login", "princess"
    ]
    
    lower_pwd = password.lower()
    for pattern in common_patterns:
        if pattern in lower_pwd:
            score -= 10
            feedback.append(f"Avoid common patterns like '{pattern}'")
            break
            
    # Cap score between 0-100
    score = max(0, min(score, 100))
    
    # Final feedback
    if score >= 80:
        strength = "strong"
    elif score >= 60:
        strength = "good"
    elif score >= 40:
        strength = "moderate"
    else:
        strength = "weak"
        
    if not feedback:
        feedback.append(f"Password strength: {strength}")
    
    return score, ", ".join(feedback)


def get_common_passwords(limit: int = 1000) -> List[str]:
    """
    Return a list of common passwords to check against.
    
    Args:
        limit: Maximum number of passwords to return
        
    Returns:
        List[str]: List of common passwords
    """
    # This is a small sample - in a real application, you would
    # load this from a file or database
    return [
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon", 
        "123123", "baseball", "abc123", "football", "monkey",
        "letmein", "696969", "shadow", "master", "666666",
        "qwertyuiop", "123321", "mustang", "1234567890", "michael",
        "654321", "superman", "1qaz2wsx", "7777777", "121212",
        "000000", "qazwsx", "123qwe", "killer", "trustno1",
        "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter",
        "buster", "soccer", "harley", "batman", "andrew",
        "tigger", "sunshine", "iloveyou", "2000", "charlie",
        "robert", "thomas", "hockey", "ranger", "daniel",
        "starwars", "klaster", "112233", "george", "computer",
        "michelle", "jessica", "pepper", "1111", "zxcvbn",
        "555555", "11111111", "131313", "freedom", "777777",
        "pass", "maggie", "159753", "aaaaaa", "ginger",
        "princess", "joshua", "cheese", "amanda", "summer",
        "love", "ashley", "nicole", "chelsea", "biteme",
        "matthew", "access", "yankees", "987654321", "dallas",
        "austin", "thunder", "taylor", "matrix", "mobilemail",
    ][:limit]


def is_common_password(password: str) -> bool:
    """
    Check if a password is in the list of common passwords.
    
    Args:
        password: Password to check
        
    Returns:
        bool: True if the password is common
    """
    common_passwords = get_common_passwords()
    return password.lower() in common_passwords


def suggest_password_improvements(password: str) -> List[str]:
    """
    Suggest improvements for a password.
    
    Args:
        password: Password to improve
        
    Returns:
        List[str]: List of improvement suggestions
    """
    score, feedback = check_password_strength(password)
    
    suggestions = []
    if "too short" in feedback:
        suggestions.append("Make the password longer (at least 12 characters)")
    
    if "lowercase" in feedback:
        suggestions.append("Add lowercase letters (a-z)")
        
    if "uppercase" in feedback:
        suggestions.append("Add uppercase letters (A-Z)")
        
    if "numbers" in feedback:
        suggestions.append("Add numbers (0-9)")
        
    if "special characters" in feedback:
        suggestions.append("Add special characters (!@#$%^&*)")
        
    if "repeated characters" in feedback:
        suggestions.append("Avoid repeating characters")
        
    if "common patterns" in feedback:
        suggestions.append("Avoid common patterns and sequences")
    
    # General advice
    if not suggestions:
        suggestions.append("Consider using a randomly generated password")
        
    return suggestions