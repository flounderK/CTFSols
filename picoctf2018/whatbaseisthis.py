import pwn
import re

s = pwn.tubes.remote.remote('2018shell.picoctf.com', 15853)
prompt = s.recvuntil('Input:\n')
word = prompt.splitlines()[1]
s.sendline(word)

prompt = s.recvuntil('Input:\n')
match = re.search(b'Please give me the ([0-9a-fA-F]+) as a word.', prompt)
hexval = match.groups()[0].decode()
word = bytes.fromhex(hexval)
s.sendline(word)


prompt = s.recvuntil('Input:\n')

matches = re.findall(b'(\d+)', prompt)
word = ''.join([chr(int(i.decode(), 8)) for i in matches]).encode()
s.sendline(word)
s.recv()
