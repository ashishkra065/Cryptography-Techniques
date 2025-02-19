from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encrypt_hybrid(plaintext, public_key):
    # Generate a random AES key
    aes_key = get_random_bytes(32)
    # Encrypt the AES key with RSA
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    # Encrypt the data with AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(plaintext.encode(), AES.block_size))
    return encrypted_aes_key + cipher_aes.iv + ciphertext

def decrypt_hybrid(ciphertext, private_key):
    # Decrypt the AES key with RSA
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = ciphertext[:rsa_key.size_in_bytes()]
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    # Decrypt the data with AES
    iv = ciphertext[rsa_key.size_in_bytes():rsa_key.size_in_bytes() + AES.block_size]
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext[rsa_key.size_in_bytes() + AES.block_size:]), AES.block_size)
    return plaintext.decode()
