import client as c
import getpass  # For secure password input

users = {}  # This will store user data. In practice, you should use a database.

def register():
    username = input("Enter a username: ")
    if username in users:
        print("Username already exists!")
        return False
    password = getpass.getpass("Enter a password: ")
    users[username] = password  # Store username and password
    print("Registration successful!")
    return True

def login():
    username = input("Enter your username: ")
    if username not in users:
        print("Username not found!")
        return None  # Ensure None is returned when login fails
    password = getpass.getpass("Enter your password: ")
    if users[username] == password:
        print("Login successful!")
        return c.User(username)  # Return the User object on successful login
    else:
        print("Wrong password!")
        return None

def main_menu():
    global user
    user = None
    while True:
        print("\n--- Main Menu ---")
        print("1. Register")
        print("2. Login")
        print("3. Send Message")
        print("4. Receive Messages")
        print("5. Exit")
        option = input("Choose an option: ")
        if option == "1":
            register()
        elif option == "2":
            user = login()
            if user:
                user.publish()  # Publishing keys, if necessary after login
        elif option in ["3", "4"] and not user:
            print("Please login first!")
        elif option == "3" and user:
            receiver=input("Enter the receiver of the message\n")

            while receiver==user.name:
                receiver=input("Cannot send message to self.\nEnter the receiver of the message\n")


            if not receiver in  user.key_bundles:
                if not user.initialHandshake(receiver) :
                    continue
                user.generateSendSecretKey(receiver)
                message=input("Enter the message to be send\n")
                user.sendInitialMessage(receiver,message)
            else: 
                message=input("Enter the message to be send\n")
                user.sendMessage(receiver,message)
        elif option == "4" and user:
            user.recvAllMessages()  # Simplified call to just display messages
        elif option == "5":
            print("Exiting...")
            break
        else:
            print("Invalid option. Please try again.")


main_menu()
