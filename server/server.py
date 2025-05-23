import socket
import threading
import base64
from encryption import hash_password, verify_password, encrypt_message, decrypt_message, generate_aes_key
from database import register_user, login_user, get_all_users, create_users_table
import hashlib

HOST = '127.0.0.1'
PORT = 15000

# Tracking dictionaries for clients and their data
clients = {}  # Format: {username: socket}
encryption_keys = {}  # Format: {socket: encryption_key}
socket_to_username = {}  # Format: {socket: username}


def start_server():
    create_users_table()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server is listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection with {addr}")
        threading.Thread(target=Handle_Client, args=(client_socket,)).start()


def handle_registration(client_socket, username, password):
    try:
        registration_successful = register_user(username, password)

        if registration_successful:
            client_socket.send("Registration successful!".encode())
            print(f"User {username} registered successfully")
        else:
            client_socket.send("Username already taken.".encode())
            print(f"Registration failed for username {username} - already taken")
    except Exception as e:
        print(f"Error during registration: {e}")
        client_socket.send(f"Registration error: {str(e)}".encode())


def generate_encryption_key(password):
    # Use SHA-256 to generate a consistent key from the password
    return hashlib.sha256(password.encode()).digest()


def handle_login(client_socket, username, password):
    try:
        login_successful = login_user(username, password)

        if not login_successful:
            client_socket.send("Login Failed! Invalid username or password.".encode())
            print(f"Login failed for user {username}")
            return

        # Generate and send encryption key
        encryption_key = generate_encryption_key(password)
        encrypted_key = base64.b64encode(encryption_key).decode()
        client_socket.send(f"Key {encrypted_key}".encode())

        # Track the user
        socket_to_username[client_socket] = username
        clients[username] = client_socket
        encryption_keys[client_socket] = encryption_key
        print(f"User {username} logged in successfully!")
    except Exception as e:
        print(f"Error during login: {e}")
        client_socket.send(f"Login error: {str(e)}".encode())


def broadcast_message(message, sender_socket=None):
    sender_username = socket_to_username.get(sender_socket, "Server")
    full_message = f"{sender_username}: {message}"

    for username, client_socket in clients.items():
        if client_socket != sender_socket:  # Don't send back to sender
            try:
                if client_socket in encryption_keys:
                    encrypted_message = encrypt_message(full_message, encryption_keys[client_socket])
                    client_socket.send(encrypted_message.encode())
                else:
                    client_socket.send(full_message.encode())
            except Exception as e:
                print(f"Error broadcasting to {username}: {e}")
                handle_client_disconnection(client_socket)


def handle_hello(client_socket, username):
    try:
        welcome_message = f"{username} joined the chat room."
        broadcast_message(welcome_message)

        # Send welcome message to the user
        personal_welcome = f"Welcome {username}!"
        if client_socket in encryption_keys:
            encrypted_personal_welcome = encrypt_message(personal_welcome, encryption_keys[client_socket])
            client_socket.send(encrypted_personal_welcome.encode())
        else:
            client_socket.send(personal_welcome.encode())
        print(f"Hello message processed for {username}")
    except Exception as e:
        print(f"Error sending welcome message: {e}")


def handle_get_users(client_socket):
    try:
        username = socket_to_username.get(client_socket, None)
        if not username:
            client_socket.send("You are not logged in.".encode())
            return

        online_users = list(clients.keys())
        users_list = f"Online users: {', '.join(online_users)}"

        if client_socket in encryption_keys:
            encryption_key = encryption_keys[client_socket]
            encrypted_users_list = encrypt_message(users_list, encryption_key)
            client_socket.send(encrypted_users_list.encode())
        else:
            client_socket.send(users_list.encode())
    except Exception as e:
        print(f"Error handling get_users: {e}")


def handle_client_disconnection(client_socket):
    try:
        username = socket_to_username.get(client_socket, None)
        if username:
            print(f"Cleaning up disconnected client: {username}")
            if username in clients:
                del clients[username]

        if client_socket in socket_to_username:
            del socket_to_username[client_socket]

        if client_socket in encryption_keys:
            del encryption_keys[client_socket]

        try:
            client_socket.close()
        except:
            pass

        if username:
            # Notify others
            leave_message = f"{username} left the chat room."
            broadcast_message(leave_message)
    except Exception as e:
        print(f"Error cleaning up client: {e}")


def handle_public_message(client_socket, encrypted_message):
    try:
        username = socket_to_username.get(client_socket, "Unknown")

        # Decrypt message if client is using encryption
        if client_socket in encryption_keys:
            try:
                message = decrypt_message(encrypted_message, encryption_keys[client_socket])
            except Exception as e:
                error_msg = f"Error decrypting message: {e}"
                client_socket.send(error_msg.encode())
                print(error_msg)
                return
        else:
            message = encrypted_message

        # Process the message format
        if "Public message, length =" not in message:
            client_socket.send("Error: Invalid message format".encode())
            return

        try:
            # Extract the actual message content
            parts = message.split(":")
            if len(parts) < 2:
                client_socket.send("Error: Invalid message format".encode())
                return

            message_body = parts[1].strip()
            print(f"Public message from {username}: {message_body}")

            # Broadcast to everyone
            broadcast_message(message_body, client_socket)
        except Exception as e:
            error_msg = f"Error processing public message format: {e}"
            client_socket.send(error_msg.encode())
            print(error_msg)
    except Exception as e:
        print(f"General error in handle_public_message: {e}")


def handle_private_message(client_socket, encrypted_message):
    try:
        sender_username = socket_to_username.get(client_socket, "Unknown")

        # Decrypt message if client is using encryption
        if client_socket in encryption_keys:
            try:
                message = decrypt_message(encrypted_message, encryption_keys[client_socket])
            except Exception as e:
                error_msg = f"Error decrypting message: {e}"
                client_socket.send(error_msg.encode())
                print(error_msg)
                return
        else:
            message = encrypted_message

        # Check message format
        if "Private message, lenght=" not in message or ", to " not in message:
            client_socket.send("Error: Invalid private message format".encode())
            return

        # Extract recipients and message body
        try:
            header_part, rest = message.split(", to ")
            recipients_part, message_body = rest.split(": \r\n", 1)

            recipients_list = [r.strip() for r in recipients_part.split(",")]
            print(f"Private message from {sender_username} to {recipients_list}: {message_body}")

            # Send the message to each recipient
            for recipient in recipients_list:
                if recipient in clients:
                    recipient_socket = clients[recipient]
                    formatted_message = f"Private from {sender_username}: {message_body}"

                    if recipient_socket in encryption_keys:
                        encrypted_response = encrypt_message(formatted_message, encryption_keys[recipient_socket])
                        recipient_socket.send(encrypted_response.encode())
                    else:
                        recipient_socket.send(formatted_message.encode())
                else:
                    # Notify sender that recipient is not online
                    feedback = f"User {recipient} is not online."
                    if client_socket in encryption_keys:
                        encrypted_feedback = encrypt_message(feedback, encryption_keys[client_socket])
                        client_socket.send(encrypted_feedback.encode())
                    else:
                        client_socket.send(feedback.encode())
        except Exception as e:
            error_msg = f"Error processing private message: {e}"
            client_socket.send(error_msg.encode())
            print(error_msg)
    except Exception as e:
        print(f"General error in handle_private_message: {e}")


def handle_logout(client_socket):
    try:
        username = socket_to_username.get(client_socket, None)
        print(f"Logout request from {username}")

        if username:
            # Remove user from tracking dictionaries
            if username in clients:
                del clients[username]

            if client_socket in socket_to_username:
                del socket_to_username[client_socket]

            if client_socket in encryption_keys:
                del encryption_keys[client_socket]

            # Broadcast logout message
            leave_message = f"{username} left the chat room."
            broadcast_message(leave_message)
            print(f"User {username} has left the chat room.")

        try:
            client_socket.close()
        except:
            pass
    except Exception as e:
        print(f"Error handling logout: {e}")


def Handle_Client(client_socket):
    try:
        while True:
            message = client_socket.recv(1024).decode()
            if not message:
                handle_client_disconnection(client_socket)
                break

            print(f"Received message: {message[:50]}...")

            # Handle different message types
            if message.startswith("Registration "):
                parts = message.split(" ", 2)
                if len(parts) == 3:
                    handle_registration(client_socket, parts[1], parts[2])
                else:
                    client_socket.send("Invalid registration format.".encode())

            elif message.startswith("Login "):
                parts = message.split(" ", 2)
                if len(parts) == 3:
                    handle_login(client_socket, parts[1], parts[2])
                else:
                    client_socket.send("Invalid login format.".encode())

            elif message.startswith("Hello "):
                parts = message.split(" ", 1)
                if len(parts) == 2:
                    handle_hello(client_socket, parts[1])
                else:
                    client_socket.send("Invalid hello format.".encode())

            elif message == "get_users":
                handle_get_users(client_socket)

            elif message == "Bye." or message == "bye":
                handle_logout(client_socket)
                break

            # For encrypted messages, check if client has encryption key
            elif client_socket in encryption_keys:
                try:
                    decrypted = decrypt_message(message, encryption_keys[client_socket])
                    if "Public message" in decrypted:
                        handle_public_message(client_socket, message)
                    elif "Private message" in decrypted:
                        handle_private_message(client_socket, message)
                    else:
                        client_socket.send("Invalid message format.".encode())
                except Exception as e:
                    print(f"Error processing encrypted message: {e}")
                    client_socket.send("Error processing encrypted message.".encode())
            else:
                client_socket.send("You need to log in first or message format is invalid.".encode())

    except Exception as e:
        print(f"Error handling client: {e}")
        handle_client_disconnection(client_socket)


if __name__ == "__main__":
    start_server()