
from aes_encrpytion import encrypt_aes, decrypt_aes
from rsa_encryption import generate_rsa_keys, encrypt_rsa, decrypt_rsa
from digital_signature import sign_data, verify_signature
from hybrid_encryption import encrypt_hybrid, decrypt_hybrid

def main():
    # Example usage of AES
    aes_key = get_random_bytes(32)
    plaintext = "Hello, AES!"
    ciphertext = encrypt_aes(plaintext, aes_key)
    print("AES Encrypted:", ciphertext)
    decrypted_text = decrypt_aes(ciphertext, aes_key)
    print("AES Decrypted:", decrypted_text)

    # Example usage of RSA
    private_key, public_key = generate_rsa_keys()
    plaintext = "Hello, RSA!"
    ciphertext = encrypt_rsa(plaintext, public_key)
    print("RSA Encrypted:", ciphertext)
    decrypted_text = decrypt_rsa(ciphertext, private_key)
    print("RSA Decrypted:", decrypted_text)

    # Example usage of Digital Signature
    data = "This is a signed message."
    signature = sign_data(data, private_key)
    print("Signature:", signature)
    is_valid = verify_signature(data, signature, public_key)
    print("Signature Valid:", is_valid)

    # Example usage of Hybrid Encryption
    plaintext = "Hello, Hybrid Encryption!"
    ciphertext = encrypt_hybrid(plaintext, public_key)
    print("Hybrid Encrypted:", ciphertext)
    decrypted_text = decrypt_hybrid(ciphertext, private_key)
    print("Hybrid Decrypted:", decrypted_text)

if __name__ == "__main__":
    main()
