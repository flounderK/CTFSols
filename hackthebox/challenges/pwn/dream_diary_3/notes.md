# DD3


## Bugs
- oob crash when printing page 0x12. Not useful
- poison null byte in edit page function
- Uninitialized Chunks
- print_page prints the output with fprintf with no size check, so any non-null characters, even pointers, are printed out as strings

## Exploit
- leak using smallest chunk size and `print_page` `fprintf` call
- Poison null byte to get overlapping chunks
- modify overlapping chunks to get arbitrary write
- write into `__free_hook`
- set register state with `setcontext`
- run shellcode that bypasses seccomp rules


## Backtrace
```
#0  0x00007f2a18eb1ed7 in raise () libc.so.6
#1  0x00007f2a18e93535 in abort () libc.so.6
#2  0x00007f2a18efa726 in ?? () libc.so.6
#3  0x00007f2a18f0159a in ?? () libc.so.6 allocator_error_panic
#4  0x00007f2a18f0181c in ?? () libc.so.6
#5  0x00007f2a18f032c7 in ?? () libc.so.6  tcache_put
#6  0x00005623e2cb78ab in ?? ()
#7  0x00005623e2cb73dd in ?? ()
#8  0x00007f2a18e94b6b in __libc_start_main () from dream_diary_3/libc.so.6
#9  0x00005623e2cb715a in ?? ()
```


## Seccomp
dumped seccomp with:
```sh
seccomp-tools dump ./diary3
```

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0012
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 0012: 0x15 0x00 0x01 0x00000055  if (A != creat) goto 0014
 0013: 0x06 0x00 0x00 0x00000000  return KILL
 0014: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```
