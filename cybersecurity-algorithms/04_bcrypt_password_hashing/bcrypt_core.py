import bcrypt

# Password input
password = b"my_secure_password"

# Hashing
salt = bcrypt.gensalt()
hashed_password = bcrypt.hashpw(password, salt)

# Verification
user_input = b"my_secure_password"
is_match = bcrypt.checkpw(user_input, hashed_password)

print("Original Password:", password)
print("Hashed Password:", hashed_password)
print("Password Match:", is_match)
