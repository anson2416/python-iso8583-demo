# Visa ISO 8583 Authorization Message Generator

This utility provides a simple way to generate ISO 8583 authorization request messages (MTI 0100) compliant with Visa standards, including support for PIN and EMV/Chip data.

The project is managed using `uv` for dependency and environment management and includes unit tests written with `pytest`.

## Features

- Generates ISO 8583 `0100` authorization messages.
- Includes mandatory fields like PAN, Amount, STAN, etc.
- Supports optional PIN Block (DE 52) and ICC/Chip Data (DE 55).
- Uses `pyiso8583` library for message construction.
- Unit tests with `pytest`.
- Project and dependency management with `uv`.

## Project Setup

Follow these steps to set up the project on your local machine.

### 1. Install `uv`

If you don't have `uv` installed, you can install it with:
```bash
pip install uv
# Or on macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Create a Virtual Environment

Create and activate a virtual environment for the project.

```bash
uv venv
source .venv/bin/activate
# On Windows: .venv\Scripts\activate
```

### 3. Install Dependencies

Install the project dependencies, including the test dependencies. The `-e .` flag installs the project in "editable" mode.

```bash
uv pip install -e .[test]
```

Manual install the python package via `uv`:

```bash
uv add pyiso8583
uv add --dev pytest
```

## Running Tests

To ensure everything is working correctly, run the unit tests using `pytest`.

```bash
uv run pytest
```

You should see the tests pass successfully.

## How to Use

You can use the `generate_visa_auth_message` function from a Python script or an interactive session.

```python
from visa_auth_generator.generator import generate_visa_auth_message

# 1. Define the transaction data
transaction_data = {
    "pan": "4111111111111111",
    "processing_code": "000000",
    "transaction_amount": 12345,  # Represents 123.45
    "stan": "123456",
    "local_transaction_time": "104530",
    "local_transaction_date": "1125",
    "expiration_date": "2812",
    "pos_entry_mode": "051", # Chip
    "acquiring_institution_id": "123456",
    "pin_data": "1122334455667788",  # 8-byte hex PIN block
    "chip_data": "9f02060000000123459f03060000000000009f1a020840950500000080009a032311259c0100" # Sample EMV data
}

# 2. Generate the message
iso_message_bytes = generate_visa_auth_message(**transaction_data)

# 3. Print the message (as a hex string for readability)
print(f"Generated ISO 8583 Message (Hex): {iso_message_bytes.hex()}")

## Understanding EMV/Chip Data (DE 55)

Data Element 55 is one of the most complex fields in a card-present (chip) transaction. It doesn't contain a single value but rather a collection of data objects from the chip card and the terminal. This data is encoded using a **Tag-Length-Value (TLV)** format.

### TLV (Tag-Length-Value) Structure

The chip data string is a concatenation of multiple TLV-encoded fields. Each field consists of:

1.  **Tag:** A unique identifier (usually 1 or 2 bytes) that specifies the type of data (e.g., `9F02` for Transaction Amount).
2.  **Length:** The length of the `Value` part, in bytes.
3.  **Value:** The actual data itself.

### Example Breakdown

Let's break down the sample `chip_data` from the test cases:

`9f02060000000123459f03060000000000009f1a020840950500000080009a032311259c0100`

This long string can be parsed into the following individual TLV components:

| Tag    | Length | Value              | Description                     |
| :----- | :----- | :----------------- | :------------------------------ |
| `9F02` | `06`   | `000000012345`     | Amount, Authorized (Numeric)    |
| `9F03` | `06`   | `000000000000`     | Amount, Other (Cashback)        |
| `9F1A` | `02`   | `0840`             | Terminal Country Code (USA)     |
| `95`   | `05`   | `0000008000`       | Terminal Verification Results   |
| `9A`   | `03`   | `231125`           | Transaction Date (YYMMDD)       |
| `9C`   | `01`   | `00`               | Transaction Type (e.g., Purchase) |

### How it Works in the Code

In `generator.py`, the `chip_data` parameter is expected to be a single hexadecimal string containing all the necessary TLV-encoded data concatenated together.

```python
chip_data_hex = "9f0206..."
iso_message.set_element('55', bytes.fromhex(chip_data_hex))
```

The function `bytes.fromhex()` converts this hex string into the raw binary format that the `pyiso8583` library and payment networks expect for binary fields like DE 55. The specific tags required in DE 55 are defined by the card schemes (Visa, Mastercard, etc.) and can vary based on the transaction type.
```