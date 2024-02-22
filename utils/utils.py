import random
import string


def get_random_string(length: int, character_set: str = string.ascii_lowercase) -> str:
    return "".join(random.choices(character_set, k=length))


def get_random_hex_string(length: int) -> str:
    character_set = "0123456789abcdef"
    return get_random_string(length, character_set)


def ip_to_bytes(ip: str) -> bytes:
    ip_bytes = b''
    for oct in ip.split("."):
        ip_bytes += int(oct).to_bytes(1, 'little')
    return ip_bytes
