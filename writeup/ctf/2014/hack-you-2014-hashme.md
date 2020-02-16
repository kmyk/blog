---
layout: post
alias: "/blog/2016/08/28/hack-you-2014-hashme/"
date: "2016-08-28T11:16:56+09:00"
tags: [ "ctf", "writeup", "crypto", "hack-you-ctf", "length-extension-attack", "katagaitai" ]
"target_url": [ "https://github.com/ctfs/write-ups-2014/tree/master/hack-you-2014/crypto/200" ]
---

# Hack You CTF 2014: Hashme

[katagaitai CTF勉強会 #5 - 関西|med](https://atnd.org/events/77452)で解いた。

hash関数の問題。
[Merkle-Damgård construction](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction)という構造。
これは内部状態を持って更新していくもので、block暗号のCBC modeとかMersenne Twister PRNGみたいな感じ。
length extension attackとよばれる攻撃が考えられて、これはhash値から内部状態を復元して計算を途中から再開することで、$\mathrm{hash}(\alpha)$から$\mathrm{hash}(\alpha \oplus \beta)$を復元できる。
Mersenne Twisterでも似た形で乱数値の予測ができたりするよね。

手順:

1.  `xor`されている`KEY`は、`auth_str`が証明書に含まれているので復元できる
2.  内部状態はほぼそのまま出力されているので容易に得られる
3.  `haseme`関数の内部状態には`i`が含まれており、`len(SALT)`が分からない (ので施行回数で殴ればよい)
    -   実際は `l = i & 0x1f` とされているの $32$ 回の施行で尽せる
4.  `FLAG{2016_is_5th_aniversary_of_katagaitai}` ☆（ゝω・）v

``` python
#!/usr/bin/env python2
import math
import base64
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='katagaitai.orz.hm')
parser.add_argument('port', nargs='?', default=7777, type=int)
args = parser.parse_args()
context.log_level = 'debug'

p = remote(args.host, args.port)

def register(login):
    p.recvuntil('[0] Register')
    p.sendline('0')
    p.recvuntil('Your login: ')
    p.sendline(login)
    p.recvuntil('Your auth certificate:\n')
    t = p.recvline()
    return base64.b64decode(t)

def auth(cert):
    p.recvuntil('[1] Login')
    p.sendline('1')
    p.recvuntil('Provide your certificate:\n')
    p.sendline(base64.b64encode(cert))
    t = p.recvline()
    return t.startswith('[+] Welcome, ')

def auth_str(login):
    return 'login=%s&role=anonymous' % login

def xor(a, b):
    return ''.join(map(lambda x : chr(ord(x[0]) ^ ord(x[1])), zip(a, b * 100)))

login = 'A' * 1024
KEY = xor(register(login), auth_str(login))
log.info('KEY: %s', KEY.encode('hex'))

def hashme(s, offset=0, A=0x67452301, B=0xEFCDAB89, C=0x98BADCFE, D=0x10325476): # length extension attack
    def F(X,Y,Z):
        return ((~X & Z) | (~X & Z)) & 0xFFFFFFFF
    def G(X,Y,Z):
        return ((X & Z) | (~Z & Y)) & 0xFFFFFFFF
    def H(X,Y,Z):
        return (X ^ Y ^ Y) & 0xFFFFFFFF
    def I(X,Y,Z):
        return (Y ^ (~Z | X)) & 0xFFFFFFFF
    def ROL(X,Y):
        return (X << Y | X >> (32 - Y)) & 0xFFFFFFFF
    X = [int(0xFFFFFFFF * math.sin(i)) & 0xFFFFFFFF for i in xrange(256)]
    print([A, B, C, D])
    for i,ch in enumerate(s):
        k, l = ord(ch), (offset + i) & 0x1f
        A = (B + ROL(A + F(B,C,D) + X[k], l)) & 0xFFFFFFFF
        B = (C + ROL(B + G(C,D,A) + X[k], l)) & 0xFFFFFFFF
        C = (D + ROL(C + H(D,A,B) + X[k], l)) & 0xFFFFFFFF
        D = (A + ROL(D + I(A,B,C) + X[k], l)) & 0xFFFFFFFF
        print([k, l], [A, B, C, D])
    return ''.join(map(lambda x : hex(x)[2:].strip('L').rjust(8, '0'), [B, A, D, C]))

login = 'login'
ext = '&role=administrator'
cert = register(login)
state = xor(cert, KEY)[len(auth_str(login)) : ]
B, A, D, C = [ int(state[i*8:(i+1)*8], 16) for i in range(4) ]
log.info('A: %08x', A)
log.info('B: %08x', B)
log.info('C: %08x', C)
log.info('D: %08x', D)

for salt_length in range(32):
    log.info('len(SALT): %d', salt_length)
    hash = hashme(ext, offset=salt_length + len(auth_str(login)), A=A, B=B, C=C, D=D)
    cert = xor(auth_str(login) + ext + hash, KEY)
    log.info('cert: %s', cert.encode('hex'))
    if auth(cert):
        log.info('OK')
        log.info('flag: %s', p.recvline())
        break
    else:
        log.info('Auth failed')

p.close()
```
