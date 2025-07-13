from visa_auth_generator.generator import generate_visa_auth_message
from visa_auth_generator.emv import create_chip_data
from datetime import datetime

if __name__ == "__main__":

    # 1. Define the base transaction data
    pan = "4111111111111111"
    amount = 12345  # Represents 123.45
    now = datetime.utcnow()

    # 2. Generate dynamic EMV chip data (DE 55)
    # NOTE: The MDK should be securely stored and managed (e.g., in a KMS or HSM).
    # This is a sample key for demonstration only.
    master_derivation_key_hex = "0123456789ABCDEFFEDCBA9876543210"
    application_transaction_counter = 22  # This should be incremented for each transaction

    chip_transaction_details = {
        "amount": amount,
        "currency_code": "0840",  # USD
        "country_code": "0840",  # USA
        "date": now.strftime('%y%m%d'),
    }

    dynamic_chip_data = create_chip_data(
        mdk_hex=master_derivation_key_hex,
        pan=pan,
        atc=application_transaction_counter,
        transaction_details=chip_transaction_details
    )

    # 3. Assemble the full ISO 8583 message data
    transaction_data = {
        "pan": pan,
        "processing_code": "000000",
        "transaction_amount": amount,
        "stan": "123457",  # Should be unique per transaction
        "local_transaction_time": now.strftime('%H%M%S'),
        "local_transaction_date": now.strftime('%m%d'),
        "expiration_date": "2812",
        "pos_entry_mode": "051",  # Chip
        "acquiring_institution_id": "123456",
        "pin_data": "1122334455667788",  # 8-byte hex PIN block
        "chip_data": dynamic_chip_data
    }

    # 4. Generate the message
    iso_message_bytes = generate_visa_auth_message(**transaction_data)

    # 5. Print the results
    print("--- Generated Chip Data (DE 55) ---")
    print(dynamic_chip_data)
    print("\n--- Full ISO 8583 Message ---")
    print(f"Generated ISO 8583 Message (Hex): {iso_message_bytes.hex()}")
