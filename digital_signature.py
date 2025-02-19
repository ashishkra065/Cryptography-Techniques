from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def sign_data(data, private_key):
    rsa_key = RSA.import_key(private_key)
    hashed_data = SHA256.new(data.encode())
    signature = pkcs1_15.new(rsa_key).sign(hashed_data)
    return signature

def verify_signature(data, signature, public_key):
    rsa_key = RSA.import_key(public_key)
    hashed_data = SHA256.new(data.encode())
    try:
        pkcs1_15.new(rsa_key).verify(hashed_data, signature)
        return True
    except (ValueError, TypeError):
        return False
