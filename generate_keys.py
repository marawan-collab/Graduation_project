from flask import Flask
from flask_mysqldb import MySQL
from dotenv import load_dotenv
import os
from signature_utils import generate_key_pair
from cryptography.hazmat.primitives import serialization

# Load environment variables
load_dotenv()

app = Flask(__name__)

# MySQL config
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'securedocs_db')

mysql = MySQL(app)

def generate_keys_for_users():
    try:
        with app.app_context():
            cur = mysql.connection.cursor()
            
            # Get all users who need keys
            cur.execute("SELECT id, username FROM users WHERE private_key IS NULL")
            users = cur.fetchall()
            
            if not users:
                print("No users found who need keys.")
                return
            
            print(f"Found {len(users)} users who need keys.")
            
            # Generate and store keys for each user
            for user_id, username in users:
                print(f"Generating keys for user: {username}")
                
                # Generate new key pair
                private_key_pem, public_key_pem = generate_key_pair()
                
                # Store both private and public keys
                cur.execute("""
                    UPDATE users 
                    SET private_key = %s,
                        public_key = %s
                    WHERE id = %s
                """, (private_key_pem, public_key_pem, user_id))
                
                print(f"Stored keys for {username}")
            
            mysql.connection.commit()
            print("Successfully generated and stored keys for all users!")
            cur.close()
            
    except Exception as e:
        print(f"Error generating keys: {str(e)}")
    finally:
        pass

if __name__ == '__main__':
    generate_keys_for_users() 