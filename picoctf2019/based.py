from pwn import *
import re 
import binascii

p = remote("2019shell1.picoctf.com", 44303)

prompt = p.read()

word = ''.join([chr(int(i, 2)) for i in re.findall('[10]+', prompt.decode())])

p.sendline(word.encode())

prompt1 = p.read()

word1 = ''.join([chr(int(i, 8)) for i in re.findall('\d+', prompt1.decode())])
p.sendline(word1.encode())
prompt2 = p.read()
word2 = binascii.unhexlify(re.search('the ([a-f0-9]+) as a word', prompt2.decode()).groups()[0])
p.sendline(word2)

prompt3 = p.read()

print(prompt3.decode())

