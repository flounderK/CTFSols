import pwn
from GizmoMaker import GizmoMaker


def write_string(gizmo_maker, method_name, start_addr: int, string: str):
    n = 4
    length = len(string)
    payload = b''
    for word in range(0, length, n):
        hexed = string[word:min(word + n, length)]
        to_addr = start_addr + word
        value = int("0x" + "".join([hex(ord(character))[2:] for character in hexed[::-1]]), 0)
        payload += gizmo_maker.execute(method_name, to_addr, value)
    return payload

