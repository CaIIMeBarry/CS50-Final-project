import re
import requests
import hashlib
import json
import csv

PASSWORD_FILE = "passwords.json"


def main():
    
    print("=" * 40)
    print(" Bardia's Password Manager and Checker")
    print("=" * 40)
    while True:
        print("\nMain Menu:")
        print("1. Password Strength Checker")
        print("2. Password Manager")
        print("3. Exit")
        choice = input("Enter your choice (1-3): ").strip()

        if choice == '1':
            run_strength_checker()
        elif choice == '2':
            run_password_manager()
        elif choice == '3':
            print("Exiting the program. Stay secure!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

def run_strength_checker():

    print("\n--- Password Strength Checker ---")
    password = input("Enter the password to check: ")
    if not password:
        print("Password cannot be empty.")
        return

    # Check local strength
    strength, feedback = check_password_strength(password)
    print(f"\nPassword Strength Score: {strength}/5")
    if not feedback:
        print("✅ This is a strong password!")
    else:
        for msg in feedback:
            print(f"- {msg}")

    # Check against HaveIBeenPwned API
    print("\nChecking for breaches (this may take a moment)...")
    try:
        pwned_count = check_pwned_api(password)
        if pwned_count > 0:
            print(f"🚨 WARNING: This password has appeared in data breaches {pwned_count:,} times. You should not use it.")
        else:
            print("✅ Good news! This password was not found in any of the data breaches checked.")
    except requests.exceptions.RequestException as e:
        print(f"Could not connect to the HaveIBeenPwned API. Please check your internet connection. Error: {e}")

def run_password_manager():
    
    print("\n--- Password Manager ---")
    
    master_pass = input("Enter master password to unlock manager: ")
    if master_pass != "0000":
        print("Incorrect master password. Access denied.")
        return

    while True:
        print("\nPassword Manager Menu:")
        print("1. Add a new password")
        print("2. Edit an existing password")
        print("3. Remove a password")
        print("4. View all saved services and passwords")
        print("5. Export passwords to CSV")
        print("6. Return to Main Menu")
        
        choice = input("Enter your choice (1-6): ").strip()
        
        if choice == '1':
            add_password()
        elif choice == '2':
            edit_password()
        elif choice == '3':
            remove_password()
        elif choice == '4':
            view_services()
        elif choice == '5':
            export_to_csv()
        elif choice == '6':
            break
        else:
            print("Invalid choice.")

def check_password_strength(password):
    
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Should be at least 12 characters long.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Missing an uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Missing a lowercase letter.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Missing a number.")
    
    if re.search(r"[\W_]", password):
        score += 1
    else:
        feedback.append("Missing a special character.")
    
    return score, feedback

def check_pwned_api(password):
   
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    
    api_url = f'https://api.pwnedpasswords.com/range/{prefix}'
    response = requests.get(api_url)
    response.raise_for_status()

    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0

def format_for_csv(passwords_dict):
    
    if not isinstance(passwords_dict, dict):
        raise TypeError("Input must be a dictionary.")

    header = ["service", "username", "password"]
    data_rows = [header]
    for service, credentials in passwords_dict.items():
        data_rows.append([
            service,
            credentials.get("username", "N/A"),
            credentials.get("password", "N/A")
        ])
    return data_rows

def load_passwords():
    
    try:
        with open(PASSWORD_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_passwords(passwords):
    
    with open(PASSWORD_FILE, "w") as f:
        json.dump(passwords, f, indent=4)

def add_password():
    
    service = input("Enter service name (e.g., Google): ").strip()
    username = input("Enter username/email for this service: ").strip()
    password = input("Enter password for this service: ")
    
    passwords = load_passwords()
    if service in passwords:
        print(f"Service '{service}' already exists. Use the edit option instead.")
        return
        
    passwords[service] = {"username": username, "password": password}
    save_passwords(passwords)
    print(f"\n **Password for '{service}' added successfully**")

def edit_password():
    
    service = input("Enter the service name to edit: ").strip()
    passwords = load_passwords()
    
    if service not in passwords:
        print(f"Service '{service}' not found.")
        return
    
    print(f"Editing service: {service}")
    print(f"Current username: {passwords[service].get('username')}")
    new_username = input("Enter new username (or press Enter to keep current): ").strip()
    new_password = input("Enter new password (or press Enter to keep current): ")

    if new_username:
        passwords[service]['username'] = new_username
    if new_password:
        passwords[service]['password'] = new_password
        
    save_passwords(passwords)
    print(f"Password for '{service}' updated.")

def remove_password():

    service = input("Enter the service name to remove: ").strip()
    passwords = load_passwords()
    
    if service in passwords:
        del passwords[service]
        save_passwords(passwords)
        print(f"\n **Password for '{service}' has been removed**")
    else:
        print(f"Service '{service}' not found.")

def view_services():
    
    passwords = load_passwords()
    if not passwords:
        print("\n **No passwords saved yet**")
        return

    print("\n--- Saved Credentials ---")
    for service, data in passwords.items():
        print(f"Service: {service}, Username: {data.get('username')}, Password: {data.get('password')}")
    print("-" * 25)

def export_to_csv():
    
    passwords = load_passwords()
    if not passwords:
        print("\n **No passwords to export**")
        return
    
    csv_data = format_for_csv(passwords)
    
    try:
        with open("passwords_export.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(csv_data)
        print("\n **Successfully exported passwords to passwords_export.csv**")
    except IOError:
        print("\n **Error: Could not write to CSV file**")

if __name__ == "__main__":
    main()

