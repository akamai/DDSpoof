import random
import string


def get_random_string(length: int, character_set: str = string.ascii_lowercase) -> str:
    return "".join(random.choices(character_set, k=length))


def get_random_hex_string(length: int) -> str:
    character_set = "0123456789abcdef"
    return get_random_string(length, character_set)
