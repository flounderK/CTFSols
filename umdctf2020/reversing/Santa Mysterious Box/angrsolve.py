#!/usr/bin/python3
import angr
import claripy
import monkeyhex
from pwn import *

# Run with ipython -i <this-filename>


class DummyHook(angr.SimProcedure):
    def run(self):
        return 0


def is_successful(state):
    return state.posix.dumps(1).find(b'Candy') > -1


def is_failure(state):
    return state.posix.dumps(1).find(b'coal!') > -1


proj_kwargs = dict()
proj_kwargs['auto_load_libs'] = False
project = angr.Project('SantaBox', **proj_kwargs)

sym_var_size_bits = 32
sym_var = claripy.BVS('sym_var0', sym_var_size_bits)


# state = project.factory.blank_state(addr=...)
state = project.factory.entry_state()
# state.regs.rax = sym_var
# state.store(sym_var_adress, sym_var)


simgr = project.factory.simgr(state)
simgr.explore(find=is_successful, avoid=is_failure)

s = simgr.one_found

print(s.posix.dumps(0))


