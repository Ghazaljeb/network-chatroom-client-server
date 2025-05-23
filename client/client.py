import socket
import base64
from encryption import encrypt_message, decrypt_message
import threading

HOST = '127.0.0.1'
PORT = 15000

encryption_key = None
is_logged_in = False  # Added missing variable


def connect_to_server():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    return client_socket


def receive_messages(client_socket):
    while True:
        try:
            encrypted_message = client_socket.recv(1024).decode()
            if not encrypted_message:
                print("Connection closed by server.")
                client_socket.close()
                break

            if encryption_key:
                # Try to decrypt the message, but handle potential decryption errors
                try:
                    message = decrypt_message(encrypted_message, encryption_key)
                    print(f"Server: {message}")
                except Exception as e:
                    # If decryption fails, show the raw message
                    print(f"Server (Encrypted or Raw): {encrypted_message}")
            else:
                print(f"Server: {encrypted_message}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            client_socket.close()
            break


def Registration(client_socket):
    username = input("Enter Username: ")
    password = input("Enter Password: ")

    client_socket.send(f"Registration {username} {password}".encode())
    response = client_socket.recv(1024).decode()
    print(response)


def Login(client_socket):
    global encryption_key, is_logged_in
    username = input("Enter Username: ")
    password = input("Enter Password: ")

    client_socket.send(f"Login {username} {password}".encode())
    response = client_socket.recv(1024).decode().strip()
    parts = response.split(" ")

    if len(parts) >= 2 and parts[0].lower() == "key":
        try:
            encrypted_key = parts[1]
            encryption_key = base64.b64decode(encrypted_key)
            is_logged_in = True  # Set login status
            print("Login successful! Encryption key received.")
            send_hello(client_socket, username)
        except Exception as e:
            print(f"Error decoding encryption key: {e}")
            encryption_key = None
            is_logged_in = False
    else:
        print(f"Login failed! Response: {response}")


def send_hello(client_socket, username):
    message = f"Hello {username}"
    client_socket.send(message.encode())
    print("Hello message sent.")


def request_user_list(client_socket):
    client_socket.send("get_users".encode())  # Fixed command to match server's expected format


def send_public_message(client_socket):
    if encryption_key is None:
        print("You need to log in first!")
        return

    message_body = input("Enter your message: ")
    message_len = len(message_body)
    formatted_message = f"Public message, length = {message_len}: {message_body}"

    encrypted_message = encrypt_message(formatted_message, encryption_key)
    client_socket.send(encrypted_message.encode())


def send_private_message(client_socket):
    if encryption_key is None:
        print("You must log in first!")
        return

    recipients = input("Enter your recipients (comma separated): ")
    message_body = input("Enter your message: ")

    message_len = len(message_body)  # Fixed to count characters, not bytes
    formatted_message = f"Private message, lenght={message_len}, to {recipients}: \r\n{message_body}"

    encrypted_message = encrypt_message(formatted_message, encryption_key)
    client_socket.send(encrypted_message.encode())


def logout(client_socket):
    global is_logged_in, encryption_key

    if encryption_key is None:
        print("You are not logged in.")
        return

    try:
        client_socket.send("Bye.".encode())
        is_logged_in = False
        encryption_key = None
        print("You have left the chat room.")
    except Exception as e:
        print(f"Error while logging out: {e}")


def main():
    client_socket = connect_to_server()
    threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

    while True:
        print("\n----- Chat Room Menu -----")
        print("1. Registration")
        print("2. Login")
        print("3. Send Public message")
        print("4. Send private message")
        print("5. Get Online Users")
        print("6. Exit")
        choice = input("Enter Your Choice: ")

        if choice == "1":
            Registration(client_socket)
        elif choice == "2":
            Login(client_socket)
        elif choice == "3":
            send_public_message(client_socket)
        elif choice == "4":
            if is_logged_in:
                send_private_message(client_socket)
            else:
                print("You must log in first!")
        elif choice == "5":
            if is_logged_in:
                request_user_list(client_socket)
            else:
                print("You must log in first!")
        elif choice == "6":
            logout(client_socket)
            print("Exiting...")
            if client_socket:
                client_socket.close()
            break
        else:
            print("Invalid Option. Try again.")


if __name__ == "__main__":
    main()
