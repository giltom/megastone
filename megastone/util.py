from dataclasses import field, MISSING

def parse_hex_int(s):
    return int(s, 16)

def hex_spaces(data):
    return ' '.join(bytes([b]).hex() for b in data)

def derived_field(default=MISSING):
    return field(init=False, default=default)