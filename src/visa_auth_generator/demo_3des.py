from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
import binascii

def pad_data(data: str) -> bytes:
    """PKCS#7 padding"""
    block_size = 8
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data.encode() + padding

def unpad_data(data: bytes) -> bytes:
    """Remove PKCS#7 padding"""
    padding_length = data[-1]
    return data[:-padding_length]

def generate_3des_key():
    """Generate a random 24-byte (triple-length) 3DES key"""
    return get_random_bytes(24)

def encrypt_pin_3des(pin: str, key: bytes) -> bytes:
    """Encrypt PIN using 3DES in ECB mode"""
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_data = pad_data(pin)
    return cipher.encrypt(padded_data)

def decrypt_pin_3des(encrypted_data: bytes, key: bytes) -> str:
    """Decrypt PIN using 3DES in ECB mode"""
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)
    unpadded_data = unpad_data(decrypted_data)
    return unpadded_data.decode()

def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes"""
    return binascii.unhexlify(hex_str.replace(' ', ''))

def decrypt_pin_from_hex(encrypted_pin_hex: str, key_hex: str) -> str:
    """
    Decrypt PIN from hex string using 3DES key in hex format
    Args:
        encrypted_pin_hex: Encrypted PIN in hex format
        key_hex: 3DES key in hex format (24 bytes / 48 hex chars)
    Returns:
        Decrypted PIN as string
    """
    try:
        encrypted_data = hex_to_bytes(encrypted_pin_hex)
        key = hex_to_bytes(key_hex)
        return decrypt_pin_3des(encrypted_data, key)
    except Exception as e:
        raise ValueError(f"Failed to decrypt PIN: {str(e)}")

def main():
    # Demo PIN encryption/decryption
    pin = "123456"
    key = generate_3des_key()
    
    print(f"Original PIN: {pin}")
    print(f"3DES Key (hex): {binascii.hexlify(key).decode()}")
    
    # Encrypt PIN
    encrypted_pin = encrypt_pin_3des(pin, key)
    print(f"Encrypted PIN (hex): {binascii.hexlify(encrypted_pin).decode()}")
    
    # Decrypt PIN
    decrypted_pin = decrypt_pin_3des(encrypted_pin, key)
    print(f"Decrypted PIN: {decrypted_pin}")

if __name__ == "__main__":
    main()
