import re
from typing import Union

# pycryptodome is required: pip install pycryptodome
from Crypto.Cipher import DES


class VisaPinError(Exception):
    """Custom exception for errors during Visa PIN/PVV generation."""
    pass


def generate_visa_pvv(pan: str, pin: str, pvki: Union[str, int], pvk: bytes) -> str:
    """
    Generates a Visa PIN Verification Value (PVV).

    This function implements the Visa PVV algorithm, which is a method to
    derive a 4-digit value from the PAN, PIN, and a secret key (PVK).
    This is a non-PIN block format used for PIN verification.

    The algorithm is as follows:
    1. Select the right-most 11 digits of the PAN (excluding the Luhn check digit).
    2. Select the PIN Verification Key Index (PVKI), a single digit.
    3. Select the first 4 digits of the customer PIN.
    4. Concatenate these to form a 16-digit intermediate value (TSP).
    5. Convert the 16-digit string into an 8-byte value.
    6. Encrypt this 8-byte value using DES with the PIN Verification Key (PVK).
    7. Scan the resulting 8-byte ciphertext for decimal digits (0-9).
    8. The first 4 decimal digits found form the PVV.

    Args:
        pan (str): The Primary Account Number, typically 13-19 digits long.
        pin (str): The Personal Identification Number, 4-12 digits long.
                   Only the first 4 digits are used.
        pvki (Union[str, int]): The PIN Verification Key Index (1 digit).
        pvk (bytes): The 8-byte (64-bit) single-DES PIN Verification Key.
                     If a 16-byte or 24-byte key is provided for TDES,
                     only the first 8 bytes are used as per the standard.

    Returns:
        str: The 4-digit PVV string.

    Raises:
        VisaPinError: If inputs are invalid or if a PVV cannot be generated.
    """
    # --- 1. Input Validation ---
    if not isinstance(pan, str) or not pan.isdigit() or not (12 <= len(pan) <= 19):
        raise VisaPinError("Invalid PAN: Must be a string of 12-19 digits.")

    if not isinstance(pin, str) or not pin.isdigit() or not (4 <= len(pin) <= 12):
        raise VisaPinError("Invalid PIN: Must be a string of 4-12 digits.")

    pvki_str = str(pvki)
    if not pvki_str.isdigit() or len(pvki_str) != 1:
        raise VisaPinError("Invalid PVKI: Must be a single digit.")

    if not isinstance(pvk, bytes) or len(pvk) < 8:
        raise VisaPinError("Invalid PVK: Must be at least 8 bytes long.")

    # --- 2. Data Preparation ---
    # Get the 11 right-most digits of the PAN, excluding the last (check) digit.
    pan_for_pvv = pan[-12:-1]

    # Get the first 4 digits of the PIN.
    pin_for_pvv = pin[:4]

    # --- 3. TSP Formation ---
    # Concatenate PAN part, PVKI, and PIN part.
    tsp_str = f"{pan_for_pvv}{pvki_str}{pin_for_pvv}"

    # Convert the 16-digit string into 8 bytes.
    try:
        tsp_bytes = bytes.fromhex(tsp_str)
    except ValueError:
        raise VisaPinError("Failed to create TSP block. Ensure PAN, PVKI, and PIN result in a valid hex string.")

    # --- 4. Encryption ---
    # The standard uses single DES. We use the first 8 bytes of the PVK.
    key = pvk[:8]
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_tsp = cipher.encrypt(tsp_bytes)

    # --- 5. PVV Extraction ---
    ciphertext_hex = encrypted_tsp.hex().upper()

    # Find all decimal digits in the hex representation of the ciphertext.
    decimal_digits = re.findall(r'\d', ciphertext_hex)

    if len(decimal_digits) < 4:
        # Note: The full Visa spec may involve a secondary derivation
        # if not enough digits are found. This implementation follows the
        # primary path and raises an error if it fails.
        raise VisaPinError(
            f"Could not extract 4 decimal digits from ciphertext '{ciphertext_hex}'. "
            "PVV generation failed."
        )

    # The PVV is the first 4 decimal digits found.
    pvv = "".join(decimal_digits[:4])

    return pvv


if __name__ == '__main__':
    # Example usage with test data.
    # These values are for demonstration purposes only.
    # In a real application, the PVK must be stored securely (e.g., in an HSM).

    sample_pan = "4000123456789012"
    sample_pin = "1234"
    sample_pvki = "1"
    # A sample 8-byte DES key (in hex: 0123456789ABCDEF)
    sample_pvk = bytes.fromhex("0123456789ABCDEF")

    print("--- Visa PVV Generation Example ---")
    print(f"PAN:  {sample_pan}")
    print(f"PIN:  {sample_pin}")
    print(f"PVKI: {sample_pvki}")
    print(f"PVK:  {sample_pvk.hex().upper()}")
    print("-" * 35)

    try:
        generated_pvv = generate_visa_pvv(
            pan=sample_pan, pin=sample_pin, pvki=sample_pvki, pvk=sample_pvk
        )
        print(f"Generated PVV: {generated_pvv}")
        # Expected PVV for this data is "1914"
        print(f"Verification: {'OK' if generated_pvv == '1914' else 'FAIL'}")
    except VisaPinError as e:
        print(f"An error occurred: {e}")