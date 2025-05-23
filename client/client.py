import socket
import base64
import threading
import time
from encryption import encrypt_message, decrypt_message, derive_key

HOST = '127.0.0.1'
PORT = 15000

class ChatClient:
    def __init__(self):
        self.client_socket = None
        self.encryption_key = None
        self.is_logged_in = False
        self.username = None
        self.running = True
        self.login_event = threading.Event()
        self.login_success = False
        self.login_error = None
        
    def connect_to_server(self):
        """Establish connection to server"""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
            print("Connected to server successfully!")
            return True
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            return False
    
    def receive_messages(self):
        """Handle incoming messages from server"""
        while self.running:
            try:
                raw = self.client_socket.recv(4096).decode()
                if not raw:
                    break

                if raw.startswith("Key ") or raw.startswith("Error"):
                    if raw.startswith("Key "):
                        b64key = raw.split(" ",1)[1]
                        self.encryption_key = base64.b64decode(b64key)
                        self.is_logged_in = True
                        self.login_success = True
                    else:
                      self.login_error = raw
                    self.login_event.set()
                else:
                    if self.encryption_key:
                        try:
                            txt = decrypt_message(raw, self.encryption_key)
                        except:
                            txt = raw
                    else:
                        txt = raw
                    print(f"Server: {txt}")                    
            except Exception as e:
                if self.running:
                    print(f"Error receiving message: {e}")
                break
    
    def send_message(self, message):
        """Send message to server with error handling"""
        try:
            if self.client_socket:
                self.client_socket.send(message.encode())
                return True
        except Exception as e:
            print(f"Error sending message: {e}")
            return False
        return False
    
    def register(self):
        """Handle user registration"""
        username = input("Enter Username: ").strip()
        password = input("Enter Password: ").strip()
        
        if not username or not password:
            print("Username and password cannot be empty!")
            return
            
        message = f"Registration {username} {password}"
        if self.send_message(message):
            print("Registration request sent. Waiting for response...")
    
    def login(self):
        username = input("Username: ")
        password = input("Password: ")
        self.username = username
        # clear any previous state
        self.login_event.clear()
        self.login_success = False
        self.login_error = None

        self.send_message(f"Login {username} {password}")
        print("Waiting for server response…")

        # wait up to 10 seconds for the Key or an Error
        if self.login_event.wait(timeout=10):
            if self.login_success:
                print("[TRUE]] Login successful!")
                # optionally send your “Hello” here
                self.send_message(f"Hello {username}")
            else:
                print(f"[FALSE] Login failed: {self.login_error}")
                self.username = None
        else:
            print("FALSE] Login timeout – no response")
            self.username = None
            
    def send_public_message(self):
        """Send public message to all users"""
        if not self.is_logged_in:
            print("You must log in first!")
            return
            
        message_body = input("Enter your message: ").strip()
        if not message_body:
            print("Message cannot be empty!")
            return
            
        formatted_message = f"Public message, length = {len(message_body)}: {message_body}"
        
        try:
            encrypted_message = encrypt_message(formatted_message, self.encryption_key)
            if self.send_message(encrypted_message.decode()):
                print("Public message sent successfully!")
        except Exception as e:
            print(f"Error sending public message: {e}")
    
    def send_private_message(self):
        """Send private message to specific users"""
        if not self.is_logged_in:
            print("You must log in first!")
            return
            
        recipients = input("Enter recipients (comma separated): ").strip()
        if not recipients:
            print("Recipients cannot be empty!")
            return
            
        message_body = input("Enter your message: ").strip()
        if not message_body:
            print("Message cannot be empty!")
            return
            
        formatted_message = f"Private message, length={len(message_body)}, to {recipients}: \r\n{message_body}"
        
        try:
            encrypted_message = encrypt_message(formatted_message, self.encryption_key)
            if self.send_message(encrypted_message.decode()):
                print("Private message sent successfully!")
        except Exception as e:
            print(f"Error sending private message: {e}")
    
    def get_online_users(self):
        """Request list of online users"""
        if not self.is_logged_in:
            print("You must log in first!")
            return
            
        if self.send_message("get_users"):
            print("Requesting online users list...")
    
    def logout(self):
        """Logout from server"""
        if not self.is_logged_in:
            print("You are not logged in.")
            return
            
        try:
            self.send_message("Bye.")
            self.is_logged_in = False
            self.encryption_key = None
            self.username = None
            print("Logged out successfully!")
        except Exception as e:
            print(f"Error during logout: {e}")
    
    def start(self):
        """Start the chat client"""
        if not self.connect_to_server():
            return
            
        # Start message receiving thread
        receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receive_thread.start()
        
        # Main menu loop
        while self.running:
            try:
                print("\n----- Chat Room Menu -----")
                print("1. Registration")
                print("2. Login")
                print("3. Send Public Message")
                print("4. Send Private Message")
                print("5. Get Online Users")
                print("6. Logout")
                print("7. Exit")
                
                choice = input("Enter your choice: ").strip()
                
                if choice == "1":
                    self.register()
                elif choice == "2":
                    self.login()
                elif choice == "3":
                    self.send_public_message()
                elif choice == "4":
                    self.send_private_message()
                elif choice == "5":
                    self.get_online_users()
                elif choice == "6":
                    self.logout()
                elif choice == "7":
                    self.running = False
                    break
                else:
                    print("Invalid choice. Please try again.")
                    
            except KeyboardInterrupt:
                print("\nExiting...")
                self.running = False
                break
            except Exception as e:
                print(f"Error in main loop: {e}")
        
        # Cleanup
        self.cleanup()
    
    def cleanup(self):
        """Clean up resources"""
        self.running = False
        if self.is_logged_in:
            self.logout()
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        print("Chat client closed.")

def main():
    client = ChatClient()
    client.start()

if __name__ == "__main__":
    main()