import bcrypt

# Simulate user registration
def register_user(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

# Simulate user login
def verify_user(stored_hash, password_attempt):
    return bcrypt.checkpw(password_attempt.encode(), stored_hash)

# Register
user_password = "superSecret123"
hashed_pw = register_user(user_password)
print("[✔] User Registered. Hash Stored.")

# Login Attempt
attempt = input("Enter your password: ")
if verify_user(hashed_pw, attempt):
    print("[✔] Access Granted!")
else:
    print("[✖] Access Denied!")
