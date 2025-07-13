from Crypto.Cipher import DES3
import binascii

def encrypt_3des_ecb(data, key):
    # Ensure key is a valid 3DES key (16 or 24 bytes, with proper parity)
    raw_key = binascii.unhexlify(key)
    # If key is 16 bytes, pad to 24 bytes by repeating first 8 bytes
    if len(raw_key) == 16:
        raw_key += raw_key[:8]
    # Validate key length
    if len(raw_key) != 24:
        raise ValueError("3DES key must be 16 or 24 bytes (32 or 48 hex chars)")
    # Ensure data is padded to multiple of 8 bytes
    data = data.ljust(8 * ((len(data) + 7) // 8), b'\x00')
    # Create 3DES cipher in ECB mode
    cipher = DES3.new(raw_key, DES3.MODE_ECB)
    # Encrypt data
    ciphertext = cipher.encrypt(data)
    return ciphertext

# Example usage
data = "4567890123451234".encode('ascii')  # Input: PAN + sequence number
key = "0123456789ABCDEF0123456789ABCDEF"  # 16-byte 3DES key (will be padded to 24 bytes)
ciphertext = encrypt_3des_ecb(data, key)
print(f"Encrypted data: {binascii.hexlify(ciphertext).decode('ascii')}")