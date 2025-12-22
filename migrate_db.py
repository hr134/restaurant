"""
Database Migration Script
Adds reset_token, reset_token_expiry, email_verified, and email_verification_code columns to User table
"""
import sqlite3
import os

# Path to database
db_path = os.path.join('instance', 'restaurant.db')

if not os.path.exists(db_path):
    print(f"[ERROR] Database not found at {db_path}")
    print("The database will be created automatically when you run app.py")
    exit(1)

try:
    # Connect to database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if columns already exist
    cursor.execute("PRAGMA table_info(user)")
    columns = [column[1] for column in cursor.fetchall()]
    
    # Add reset_token column if it doesn't exist
    if 'reset_token' not in columns:
        print("Adding reset_token column...")
        cursor.execute("ALTER TABLE user ADD COLUMN reset_token VARCHAR(100)")
        print("[SUCCESS] reset_token column added")
    
    # Add reset_token_expiry column if it doesn't exist
    if 'reset_token_expiry' not in columns:
        print("Adding reset_token_expiry column...")
        cursor.execute("ALTER TABLE user ADD COLUMN reset_token_expiry DATETIME")
        print("[SUCCESS] reset_token_expiry column added")

    # Add email_verified column if it doesn't exist
    if 'email_verified' not in columns:
        print("Adding email_verified column...")
        cursor.execute("ALTER TABLE user ADD COLUMN email_verified BOOLEAN DEFAULT 0")
        print("[SUCCESS] email_verified column added")

    # Add email_verification_code column if it doesn't exist
    if 'email_verification_code' not in columns:
        print("Adding email_verification_code column...")
        cursor.execute("ALTER TABLE user ADD COLUMN email_verification_code VARCHAR(10)")
        print("[SUCCESS] email_verification_code column added")

    # Add created_at column if it doesn't exist
    if 'created_at' not in columns:
        print("Adding created_at column...")
        cursor.execute("ALTER TABLE user ADD COLUMN created_at DATETIME")
        
        # Set default value for existing rows (current time)
        from datetime import datetime
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(f"UPDATE user SET created_at = '{now}' WHERE created_at IS NULL")
        
        print("[SUCCESS] created_at column added")

    # Add member_id column if it doesn't exist
    if 'member_id' not in columns:
        print("Adding member_id column...")
        cursor.execute("ALTER TABLE user ADD COLUMN member_id VARCHAR(20)")
        
        # Generate member_id for existing users
        print("Generating member_ids for existing users...")
        cursor.execute("SELECT id FROM user")
        users = cursor.fetchall()
        import random
        for u in users:
            uid = u[0]
            # Format: 75 + 2 random digits + id
            mid = f"75{random.randint(10, 99)}{uid}"
            cursor.execute(f"UPDATE user SET member_id = '{mid}' WHERE id = {uid}")
            
        print("[SUCCESS] member_id column added and populated")

    # Commit changes
    conn.commit()
    print("\n[SUCCESS] Database migration completed successfully!")
    print("You can now run the application with: python app.py")
    
    # Close connection
    conn.close()
    
except sqlite3.Error as e:
    print(f"[ERROR] Database error: {e}")
    exit(1)
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    exit(1)
