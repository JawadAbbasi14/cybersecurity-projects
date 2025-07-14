# A simple simulation of secure chat using RSA
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate key pair for Alice and Bob
def generate_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    return private, public

# Encrypt message
def encrypt_message(public_key, msg):
    return public_key.encrypt(
        msg.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Decrypt message
def decrypt_message(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

# Simulate
alice_private, alice_public = generate_keys()
bob_private, bob_public = generate_keys()

msg_from_alice = "Hello Bob, this is secret."
encrypted_msg = encrypt_message(bob_public, msg_from_alice)
print("[Encrypted]:", encrypted_msg)

decrypted_msg = decrypt_message(bob_private, encrypted_msg)
print("[Decrypted by Bob]:", decrypted_msg)
