from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.backends import default_backend
from typing import Dict, Any

def generate_arqc(session_key: bytes, transaction_data: bytes) -> bytes:
    """
    Generates an ARQC using AES-CMAC.
    NOTE: Real EMV uses 3DES-MAC (Retail MAC), but AES-CMAC is a modern,
    secure equivalent available in the `cryptography` library and serves
    to demonstrate the principle of MAC generation.

    Args:
        session_key (bytes): The 16-byte session key.
        transaction_data (bytes): The concatenated transaction data to be authenticated.

    Returns:
        bytes: The 8-byte ARQC.
    """
    # Pad data to be a multiple of the block size (16 bytes for AES)
    # ISO/IEC 9797-1 Padding Method 2: append 0x80 and then 0x00 bytes
    padded_data = transaction_data + b'\x80'
    while len(padded_data) % 16 != 0:
        padded_data += b'\x00'

    c = cmac.CMAC(algorithms.AES(session_key), backend=default_backend())
    c.update(padded_data)
    full_mac = c.finalize()
    return full_mac[:8] # ARQC is typically 8 bytes

def build_tlv(tag: str, value: str) -> str:
    """Builds a single TLV component."""
    # Ensure value is a hex string
    value_bytes = bytes.fromhex(value)
    # Length is the number of bytes in the value
    length_hex = f"{len(value_bytes):02x}" # Assuming length fits in one byte
    return tag + length_hex + value

def create_chip_data(
    mdk_hex: str,
    pan: str,
    atc: int,
    transaction_details: Dict[str, Any]
) -> str:
    """
    Creates the full DE 55 chip data string, including a generated ARQC.
    This function uses a simplified key derivation scheme for demonstration purposes.

    Args:
        mdk_hex (str): The 32-char hex representation of the 16-byte MDK.
        pan (str): The Primary Account Number.
        atc (int): The Application Transaction Counter.
        transaction_details (Dict[str, Any]): A dictionary of other transaction data.
            Example: {'amount': 12345, 'currency_code': '0840', 'country_code': '0840', 'date': '231125'}

    Returns:
        str: The concatenated hex string for DE 55.
    """
    mdk = bytes.fromhex(mdk_hex)

    # 1. Derive a session key (simplified example)
    # A real implementation would use a more complex, scheme-defined derivation.
    # This example uses 3DES to encrypt a value derived from the ATC.
    if len(mdk) != 16:
        raise ValueError("MDK must be 16 bytes (32 hex characters).")
    
    key_3des = mdk + mdk[:8] # Create a 24-byte key for 3DES from the 16-byte MDK
    cipher = Cipher(TripleDES(key_3des), mode=modes.ECB(), backend=default_backend())
    
    # Data to encrypt: ATC (2 bytes) + 6 bytes of padding to make 8 bytes (block size)
    atc_bytes = atc.to_bytes(2, 'big')
    derivation_input_1 = atc_bytes + b'\x00' * 6
    encryptor_1 = cipher.encryptor()
    session_key_part1 = encryptor_1.update(derivation_input_1) + encryptor_1.finalize()

    # Create a second part of the key for a 16-byte session key
    derivation_input_2 = atc_bytes + b'\xFF' * 6
    encryptor_2 = cipher.encryptor()
    session_key_part2 = encryptor_2.update(derivation_input_2) + encryptor_2.finalize()

    session_key = session_key_part1 + session_key_part2 # 16-byte session key

    # 2. Prepare data for ARQC calculation (based on CDOL1)
    amount_str = f"{transaction_details['amount']:012d}"
    currency_code = transaction_details['currency_code']
    country_code = transaction_details['country_code']
    tvr = "0000008000" # Terminal Verification Results (example)
    tx_date = transaction_details['date'] # YYMMDD
    tx_type = "00" # Purchase
    unpredictable_num = "12345678" # Example
    atc_hex = f"{atc:04x}"

    arqc_data_str = (amount_str + "000000000000" + country_code + tvr + currency_code + tx_date + tx_type + unpredictable_num + atc_hex)
    arqc_data_bytes = bytes.fromhex(arqc_data_str)

    # 3. Generate the ARQC
    arqc = generate_arqc(session_key, arqc_data_bytes)

    # 4. Assemble the DE 55 TLV string
    tlv_components = [
        build_tlv("9F02", amount_str),           # Amount, Authorized
        build_tlv("9F03", "000000000000"),       # Amount, Other
        build_tlv("9F1A", country_code),         # Terminal Country Code
        build_tlv("95", tvr),                    # Terminal Verification Results
        build_tlv("5F2A", currency_code),        # Transaction Currency Code
        build_tlv("9A", tx_date),                # Transaction Date
        build_tlv("9C", tx_type),                # Transaction Type
        build_tlv("9F37", unpredictable_num),    # Unpredictable Number
        build_tlv("9F36", atc_hex),              # Application Transaction Counter (ATC)
        build_tlv("9F26", arqc.hex()),           # Application Cryptogram (ARQC)
    ]

    return "".join(tlv_components)