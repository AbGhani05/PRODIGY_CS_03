import re

def check_password_complexity(password):
    # Defining regular expressions for different password complexity rules
    length_regex = re.compile(r'.{8,}')  # At least 8 characters long
    uppercase_regex = re.compile(r'[A-Z]')  # Contains at least one uppercase letter
    lowercase_regex = re.compile(r'[a-z]')  # Contains at least one lowercase letter
    digit_regex = re.compile(r'\d')  # Contains at least one digit
    special_char_regex = re.compile(r'[!@#$%^&*()\-_=+{};:,<.>/?\[\]\'\"\\|`]')  # Contains at least one special character

    # Checking each complexity rule
    if not length_regex.search(password):
        return False, "Password must be at least 8 characters long"
    if not uppercase_regex.search(password):
        return False, "Password must contain at least one uppercase letter"
    if not lowercase_regex.search(password):
        return False, "Password must contain at least one lowercase letter"
    if not digit_regex.search(password):
        return False, "Password must contain at least one digit"
    if not special_char_regex.search(password):
        return False, "Password must contain at least one special character"

    return True, "Password meets complexity requirements"

# Example usage
password = input("Enter a password to check its complexity: ")

valid, message = check_password_complexity(password)

if valid:
    print("Password is valid")
else:
    print(f"Password is invalid: {message}")
