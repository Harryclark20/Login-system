import tkinter as tk
import hashlib
import re

def is_valid_email(email):
    regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]+$"
    if re.match(regex, email):
        return True
    else:
        return False

def is_valid_phone_number(phone_number):
    if len(phone_number) != 11:
        return False
    else:
        return True

def validate_user_input(phone_number, email_address):
    error_message = ""

    # Check if the email address is valid
    if not is_valid_email(email_address):
        error_message += "Invalid email address\n"

    # Check if the phone number is valid
    if not is_valid_phone_number(phone_number):
        error_message += "Phone number must be 11 digits long\n"

    # Flag an error if one or both phone number and email address are wrong
    if error_message != "":
        raise ValueError(error_message)

users = {}
email = {}

def register():
    username = input("Enter username: ")
    password = input("Enter password: ")
    phone_number = input("Enter phone number: ")
    email_address = input("Enter your email address: ")

    try:
        validate_user_input(phone_number, email_address)
    except ValueError as e:
        print(e)
        return

    # Generate a password hash
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    # Check if the username already exists
    if username in users:
        print("Username already exists")
        return

    # Add the user to the dictionary
    users[username] = password_hash

    # Add the email address to the dictionary
    email[username] = email_address

    print("User registered successfully")


def login():
    username = input("Enter username: ")
    password = input("Enter password: ")

    # Check if the username exists
    if username not in users:
        print("Username does not exist")
        return

    # Get the password hash from the dictionary
    password_hash = users[username]

    # Check if the password matches
    if password_hash == hashlib.sha256(password.encode()).hexdigest():
        print("Login successful")
        return
    print("Invalid username or password")


def main():
    print("1. Register")
    print("2. Login")
    print("3. Exit")
    choice = input("Enter your choice: ")

    if choice == "1":
        register()
    elif choice == "2":
        login()
    elif choice == "3":
        exit()
    else:
        print("Invalid choice")


if __name__ == "__main__":
    main()
