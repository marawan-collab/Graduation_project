from flask import Flask
from flask_mysqldb import MySQL
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

app = Flask(__name__)

# MySQL config
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'securedocs_db')

mysql = MySQL(app)

def update_database():
    try:
        with app.app_context():
            cur = mysql.connection.cursor()
            
            # Add signature-related columns to documents table
            cur.execute("""
                ALTER TABLE documents
                ADD COLUMN signature_time TIMESTAMP NULL,
                ADD COLUMN signed_by INT NULL,
                ADD FOREIGN KEY (signed_by) REFERENCES users(id) ON DELETE SET NULL
            """)
            print("Added signature columns to documents table")
            
            # Add private key column to users table
            cur.execute("""
                ALTER TABLE users
                ADD COLUMN private_key TEXT NULL
            """)
            print("Added private_key column to users table")
            
            # Create index for faster signature lookups
            cur.execute("""
                CREATE INDEX idx_documents_signature ON documents(signature_time)
            """)
            print("Created signature index")
            
            mysql.connection.commit()
            print("Database schema updated successfully!")
            
    except Exception as e:
        print(f"Error updating database: {str(e)}")
    finally:
        cur.close()

if __name__ == '__main__':
    update_database() 