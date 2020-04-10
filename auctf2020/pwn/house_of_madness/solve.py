#!/usr/bin/python3
from pwn import *
import importlib
import monkeyhex
import time
import exploit_payload

context.terminal = ['termite', '-e']
binary = ELF('challenge')
# p = remote('challenges.auctf.com', 30012)

def get_base(room4_addr):
    binary = ELF('challenge')
    base_addr = room4_addr - binary.sym['room4']
    return base_addr


def run_exploit(self, *args, **kwargs):
    """Wrapper to speed up payload dev"""
    try:
        importlib.reload(exploit_payload)
    except:
        print("failed to reload")
        return
    return exploit_payload.exploit(self, *args, **kwargs)


def new_proc(start_gdb=True):
    p = process(['./challenge'])
    # p = remote('challenges.auctf.com', 30012)
    if start_gdb is True:
        gdb.attach(p, """p room4
                   """)
    # Bind function to p
    p.run_exploit = run_exploit.__get__(p)

    return p


p = new_proc()
# p.sendline(payload)




