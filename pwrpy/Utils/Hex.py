class Hex:
    @staticmethod
    def decode(hex_string):
        if hex_string is None or not hex_string:
            return b''

        cleaned_hex_string = hex_string[2:] if hex_string.startswith('0x') else hex_string

        if len(cleaned_hex_string) % 2 != 0:
            raise ValueError(f"Invalid hexadecimal string: {hex_string}")

        return bytes.fromhex(cleaned_hex_string)

    @staticmethod
    def to_hex_string(bytes_data):
        if bytes_data is None:
            return None

        return bytes_data.hex().upper()