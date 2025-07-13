from Crypto.Cipher import DES3
import binascii

def encrypt_3des_ecb(data, key):
    # Ensure data is padded to multiple of 8 bytes
    data = data.ljust(8 * ((len(data) + 7) // 8), b'\x00')
    # Create 3DES cipher in ECB mode
    cipher = DES3.new(binascii.unhexlify(key), DES3.MODE_ECB)
    # Encrypt data
    ciphertext = cipher.encrypt(data)
    return ciphertext

# Example usage
data = "4567890123451234".encode('ascii')  # Input: PAN + sequence number
key = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"  # 24-byte 3DES key
ciphertext = encrypt_3des_ecb(data, key)
print(f"Encrypted data: {binascii.hexlify(ciphertext).decode('ascii')}")