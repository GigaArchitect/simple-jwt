from hashlib import sha256


def number_to_repeated_bytes(number, byte_length, byteorder='big', signed=False):
    num_bytes = number.to_bytes(
        (number.bit_length() + 7) // 8 or 1, byteorder=byteorder, signed=signed)

    if len(num_bytes) < byte_length:
        repetitions = (byte_length + len(num_bytes) - 1) // len(num_bytes)
        num_bytes = (num_bytes * repetitions)[:byte_length]

    return num_bytes


def hmac(key: str, message: str):
    opad = 0x5c
    ipad = 0x36
    blocksize = 64
    encoded_key = key.encode()
    encoded_opad = number_to_repeated_bytes(opad, blocksize)
    encoded_ipad = number_to_repeated_bytes(ipad, blocksize)

    if len(encoded_key) < blocksize:
        encoded_key = encoded_key.ljust(blocksize, b'\x00')
    if len(encoded_key) > blocksize:
        encoded_key = sha256(encoded_key).digest()

    key_opad = bytes([b1 ^ b2 for b1, b2 in zip(encoded_key, encoded_opad)])
    key_ipad = bytes([b1 ^ b2 for b1, b2 in zip(encoded_key, encoded_ipad)])

    return sha256(key_opad + sha256(key_ipad + message.encode()).digest()).digest()


if __name__ == "__main__":
    print(hmac("BBBB", "SUCK IT").hex())
