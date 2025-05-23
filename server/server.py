import socket
import threading
import base64
import time
from encryption import encrypt_message, decrypt_message, derive_key
from database import register_user, login_user, get_all_users, user_exists

HOST = '127.0.0.1'
PORT = 15000

class ChatServer:
    def __init__(self):
        self.clients = {}  # Format: {username: socket}
        self.encryption_keys = {}  # Format: {socket: encryption_key}
        self.socket_to_username = {}  # Format: {socket: username}
        self.server_socket = None
        self.running = True
        self.client_lock = threading.RLock()


    def start_server(self):
        """Start the chat server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((HOST, PORT))
            self.server_socket.listen(10)  # Increased connection queue
            print(f"Chat server started on {HOST}:{PORT}")
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    print(f"New connection from {addr}")
                    
                    # Start client handler thread
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_socket,),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        print(f"Error accepting connection: {e}")
                    
        except Exception as e:
            print(f"Error starting server: {e}")
        finally:
            self.cleanup_server()
    
    def handle_registration(self, client_socket, username, password):
        """Handle user registration"""
        try:
            if not username or not password:
                client_socket.send("Registration failed: Username and password required.".encode())
                return
            
            success = register_user(username, password)
            
            if success:
                client_socket.send("Registration successful! You can now log in.".encode())
                print(f"User '{username}' registered successfully")
            else:
                client_socket.send("Registration failed: Username already exists.".encode())
                print(f"Registration failed for '{username}' - username taken")
                
        except Exception as e:
            print(f"Error during registration: {e}")
            client_socket.send("Registration failed: Server error.".encode())
    
    def handle_login(self, client_socket, username, password):
        """Handle user login"""
        try:
            if not username or not password:
                client_socket.send("Login failed: Username and password required.".encode())
                return
            
            # Check if user is already logged in
            with self.client_lock:
                if username in self.clients:
                    client_socket.send("Login failed: User already logged in.".encode())
                    return
            
            success = login_user(username, password)
            
            if success:
                # Generate encryption key from password
                encryption_key = derive_key(password)
                encrypted_key = base64.b64encode(encryption_key).decode()
                
                # Track the user
                with self.client_lock:
                    self.socket_to_username[client_socket] = username
                    self.clients[username] = client_socket
                    self.encryption_keys[client_socket] = encryption_key
                
                # Send success response with encryption key
                client_socket.send(f"Key {encrypted_key}".encode())
                print(f"User '{username}' logged in successfully")
                
            else:
                client_socket.send("Login failed: Invalid username or password.".encode())
                print(f"Login failed for '{username}' - invalid credentials")
                
        except Exception as e:
            print(f"Error during login: {e}")
            client_socket.send("Login failed: Server error.".encode())
    
    def handle_hello(self, client_socket, username):
        """Handle user join announcement"""
        try:
            with self.client_lock:
                # Verify user is logged in
                if client_socket not in self.socket_to_username:
                    client_socket.send("Error: Not logged in.".encode())
                    return
                
                actual_username = self.socket_to_username[client_socket]
                if actual_username != username:
                    client_socket.send("Error: Username mismatch.".encode())
                    return
            
            # Send welcome message to user
            welcome_msg = f"Welcome to the chat room, {username}!"
            self.send_encrypted_message(client_socket, welcome_msg)
            
            # Announce user joined to everyone else
            join_msg = f"{username} joined the chat room."
            self.broadcast_message(join_msg, exclude_socket=client_socket)
            
            print(f"User '{username}' joined the chat room")
            
        except Exception as e:
            print(f"Error handling hello: {e}")
    
    def handle_get_users(self, client_socket):
        """Send list of online users"""
        try:
            with self.client_lock:
                if client_socket not in self.socket_to_username:
                    client_socket.send("Error: Not logged in.".encode())
                    return
                
                online_users = list(self.clients.keys())
            
            users_list = f"Online users ({len(online_users)}): {', '.join(sorted(online_users))}"
            self.send_encrypted_message(client_socket, users_list)
            
        except Exception as e:
            print(f"Error handling get_users: {e}")
    
    def handle_public_message(self, client_socket, encrypted_message):
        """Handle public message broadcast"""
        try:
            with self.client_lock:
                print(encrypted_message)
                username = self.socket_to_username.get(client_socket)
                print(username)
                if not username:
                    client_socket.send("Error: Not logged in.".encode())
                    return
            # Decrypt the message
            decrypted_msg = decrypt_message(encrypted_message, self.encryption_keys[client_socket])
            
            # Parse message format: "Public message, length = X: message_body"
            if not decrypted_msg.startswith("Public message, length ="):
                self.send_encrypted_message(client_socket, "Error: Invalid public message format.")
                return
            
            # Extract message body
            colon_pos = decrypted_msg.find(": ")
            if colon_pos == -1:
                self.send_encrypted_message(client_socket, "Error: Invalid message format.")
                return
            
            message_body = decrypted_msg[colon_pos + 2:]
            
            # Broadcast to all users
            broadcast_msg = f"{username}: {message_body}"
            self.broadcast_message(broadcast_msg, exclude_socket=client_socket)
            
            print(f"Public message from '{username}': {message_body}")
            
        except Exception as e:
            print(f"Error handling public message: {e}")
            self.send_encrypted_message(client_socket, "Error processing public message.")
    
    def handle_private_message(self, client_socket, encrypted_message):
        """Handle private message to specific users"""
        try:
            with self.client_lock:
                sender_username = self.socket_to_username.get(client_socket)
                if not sender_username:
                    client_socket.send("Error: Not logged in.".encode())
                    return
            
            # Decrypt the message
            decrypted_msg = decrypt_message(encrypted_message, self.encryption_keys[client_socket])
            
            # Parse format: "Private message, length=X, to recipients: \r\nmessage_body"
            if not decrypted_msg.startswith("Private message, length="):
                self.send_encrypted_message(client_socket, "Error: Invalid private message format.")
                return
            
            # Extract recipients and message body
            parts = decrypted_msg.split(": \r\n", 1)
            if len(parts) != 2:
                self.send_encrypted_message(client_socket, "Error: Invalid message format.")
                return
            
            header = parts[0]
            message_body = parts[1]
            
            # Extract recipients from header
            to_pos = header.find(", to ")
            if to_pos == -1:
                self.send_encrypted_message(client_socket, "Error: Recipients not found.")
                return
            
            recipients_str = header[to_pos + 5:]  # Skip ", to "
            recipients = [r.strip() for r in recipients_str.split(",")]
            
            # Send to each recipient
            sent_count = 0
            with self.client_lock:
                for recipient in recipients:
                    if recipient in self.clients:
                        recipient_socket = self.clients[recipient]
                        private_msg = f"Private from {sender_username}: {message_body}"
                        self.send_encrypted_message(recipient_socket, private_msg)
                        sent_count += 1
                    else:
                        # Notify sender that recipient is offline
                        error_msg = f"User '{recipient}' is not online."
                        self.send_encrypted_message(client_socket, error_msg)
            
            if sent_count > 0:
                self.send_encrypted_message(client_socket, f"Private message sent to {sent_count} user(s).")
            
            print(f"Private message from '{sender_username}' to {recipients}: {message_body}")
            
        except Exception as e:
            print(f"Error handling private message: {e}")
            self.send_encrypted_message(client_socket, "Error processing private message.")
    
    def handle_logout(self, client_socket):
        """Handle user logout"""
        try:
            with self.client_lock:
                username = self.socket_to_username.get(client_socket)
                if username:
                    # Remove from tracking
                    if username in self.clients:
                        del self.clients[username]
                    del self.socket_to_username[client_socket]
                    if client_socket in self.encryption_keys:
                        del self.encryption_keys[client_socket]
                    
                    print(f"User '{username}' logged out")
                    
                    # Announce departure
                    leave_msg = f"{username} left the chat room."
                    self.broadcast_message(leave_msg)
            
            # Close connection
            try:
                client_socket.close()
            except:
                pass
                
        except Exception as e:
            print(f"Error handling logout: {e}")
    
    def send_encrypted_message(self, client_socket, message):
        """Send encrypted message to a specific client"""
        try:
            if client_socket in self.encryption_keys:
                encrypted_msg = encrypt_message(message, self.encryption_keys[client_socket])
                client_socket.send(encrypted_msg)
            else:
                client_socket.send(message.encode())
        except Exception as e:
            print(f"Error sending encrypted message: {e}")
            self.handle_client_disconnection(client_socket)
    
    def broadcast_message(self, message, exclude_socket=None):
        """Broadcast message to all connected clients"""
        with self.client_lock:
            clients_copy = self.clients.copy()
        
        for username, client_socket in clients_copy.items():
            if client_socket != exclude_socket:
                try:
                    self.send_encrypted_message(client_socket, message)
                except Exception as e:
                    print(f"Error broadcasting to '{username}': {e}")
                    self.handle_client_disconnection(client_socket)
    
    def handle_client_disconnection(self, client_socket):
        """Clean up when client disconnects"""
        try:
            with self.client_lock:
                username = self.socket_to_username.get(client_socket)
                
                # Remove from all tracking dictionaries
                if username and username in self.clients:
                    del self.clients[username]
                
                if client_socket in self.socket_to_username:
                    del self.socket_to_username[client_socket]
                
                if client_socket in self.encryption_keys:
                    del self.encryption_keys[client_socket]
            
            # Close socket
            try:
                client_socket.close()
            except:
                pass
            
            if username:
                print(f"User '{username}' disconnected")
                # Announce departure
                leave_msg = f"{username} left the chat room."
                self.broadcast_message(leave_msg)
                
        except Exception as e:
            print(f"Error handling client disconnection: {e}")
    
    def handle_client(self, client_socket):
        """Handle individual client connection"""
        try:
            while self.running:
                try:
                    # Set socket timeout to prevent hanging
                    client_socket.settimeout(300.0)  # 5 minutes timeout
                    message = client_socket.recv(1024).decode().strip()
                    
                    if not message:
                        break
                    
                    print(f"Received: {message[:100]}...")  # Log first 100 chars
                    
                    # Parse and handle different message types
                    if message.startswith("Registration "):
                        parts = message.split(" ", 2)
                        if len(parts) == 3:
                            self.handle_registration(client_socket, parts[1], parts[2])
                        else:
                            client_socket.send("Error: Invalid registration format.".encode())
                    
                    elif message.startswith("Login "):
                        parts = message.split(" ", 2)
                        if len(parts) == 3:
                            self.handle_login(client_socket, parts[1], parts[2])
                        else:
                            client_socket.send("Error: Invalid login format.".encode())
                    
                    elif message.startswith("Hello "):
                        parts = message.split(" ", 1)
                        if len(parts) == 2:
                            self.handle_hello(client_socket, parts[1])
                        else:
                            client_socket.send("Error: Invalid hello format.".encode())
                    
                    elif message == "get_users":
                        self.handle_get_users(client_socket)
                    
                    elif message in ["Bye.", "bye", "quit", "exit"]:
                        self.handle_logout(client_socket)
                        break
                    
                    else:
                        # Handle encrypted messages (public/private)
                        with self.client_lock:
                            if client_socket in self.encryption_keys:
                                try:
                                    print(1)
                                    # Try to decrypt to determine message type
                                    decrypted = decrypt_message(message, self.encryption_keys[client_socket])
                                    print(decrypted)
                                    if "Public message" in decrypted:
                                        self.handle_public_message(client_socket, message)
                                    elif "Private message" in decrypted:
                                        self.handle_private_message(client_socket, message)
                                    else:
                                        self.send_encrypted_message(client_socket, "Error: Unknown message type.")
                                        
                                except Exception as e:
                                    print(f"Error processing encrypted message: {e}")
                                    self.send_encrypted_message(client_socket, "Error: Could not process message.")
                            else:
                                client_socket.send("Error: Not logged in or invalid message format.".encode())
                
                except socket.timeout:
                    print("Client connection timed out")
                    break
                except Exception as e:
                    print(f"Error in client handler: {e}")
                    break
                    
        except Exception as e:
            print(f"Fatal error in client handler: {e}")
        finally:
            self.handle_client_disconnection(client_socket)
    
    def cleanup_server(self):
        """Clean up server resources"""
        print("Shutting down server...")
        self.running = False
        
        # Close all client connections
        with self.client_lock:
            for client_socket in list(self.socket_to_username.keys()):
                try:
                    client_socket.close()
                except:
                    pass
            
            self.clients.clear()
            self.socket_to_username.clear()
            self.encryption_keys.clear()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("Server shut down complete.")
    
    def get_server_stats(self):
        """Get current server statistics"""
        with self.client_lock:
            return {
                'online_users': len(self.clients),
                'connected_sockets': len(self.socket_to_username),
                'users': list(self.clients.keys())
            }

def main():
    global running
    """Main server function"""
    server = ChatServer()
    
    try:
        print("Starting Chat Server...")
        server.start_server()
    except KeyboardInterrupt:
        print("\nCtrl+C received — shutting down server...")
        running = False

        # Clean up client connections
        for conn in server.clients:
            try:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
            except:
                pass

        print("Server has shut down gracefully.")
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server.cleanup_server()

if __name__ == "__main__":
    main()