---
layout: post
redirect_from:
  - /writeup/ctf/2017/twctf-2017-babypinhole/
  - /blog/2017/09/04/twctf-2017-babypinhole/
date: "2017-09-04T13:34:15+09:00"
tags: [ "ctf", "writeup", "twctf", "crypto", "paillier-cryptosystem", "homomorphic-property", "hardcore-bit" ]
---

# Tokyo Westerns CTF 3rd 2017: BabyPinhole

-   こういう話があった: <https://twitter.com/elliptic_shiho/status/907221511173312513>
-   加法のそれを使ってshiftしていい感じにしてるだけだからPaillier暗号である必然性はないよね、ぐらいの気持ち
-   この手のアレはHardcore Bitとか言うそうな
    -   <https://twitter.com/elliptic_shiho/status/907226225357111298>
    -   <https://crypto.stanford.edu/pbc/notes/crypto/hardcore.html>

## problem

[Paillier暗号](https://ja.wikipedia.org/wiki/Paillier%E6%9A%97%E5%8F%B7)による公開鍵$(n, g)$と暗号文$c$が与えられている。
整数$b$が固定されており、復号結果の$b$-bit目を返すoracleがある。
$c$を復号せよ。

## solution

準同型性(加法)をやる。

Paillier暗号は準同型性を持つ: $\mathrm{enc}(m\_1 ; r\_1) \mathrm{enc}(m\_2 ; r\_2) = \mathrm{enc}(m\_1 + m\_2 ; r\_1 r\_2)$。
$\mathrm{oracle}(c \cdot \mathrm{enc}(\delta ; r\_2))$とすれば$c + \delta$の復号結果の$b$-bit目が得られる。
$\delta = 2^{b-1}$として$\mathrm{oracle}(c ) \ne \mathrm{oracle}(c \cdot \mathrm{enc}(2^{b-1} ; r\_2))$であれば$m + 2^{b-1}$としたときに繰り上がりが発生していたことになり、つまり$m$の$b-1$-bit目は$1$であるかどうかが分かる。
繰り上がりが発生したかどうかで$b$-bit目が変わるように$\delta$を決めて繰り返していけばflagが取れる。
flagの後半については単純にすればよい。flagの前半については$\bmod N$のoverflowが効いてくるので少し手間だが、やればなんとかなる。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='ppc2.chal.ctf.westerns.tokyo')
parser.add_argument('port', nargs='?', default=38264, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level

# params
from Crypto.Util.number import *
from hashlib import sha1
bits = 1024
def LCM(x, y):
    return x * y // GCD(x, y)
def L(x, n):
    return (x - 1) // n
def encrypt(m, r):
    m %= n2
    assert 1 <= r < n2
    c = pow(g, m, n2) * pow(r, n, n2) % n2
    return c
def complement(s):
    return ''.join(map(lambda c: str(1 - int(c)), s))
with open('publickey') as fh:
    n = int(fh.readline(), 16)
    n2 = int(fh.readline(), 16)
    g = int(fh.readline(), 16)
with open('ciphertext') as fh:
    ciphertext = int(fh.readline(), 16)

# connect
p = remote(args.host, args.port)
def oracle(c, memo={}):
    c %= n2
    assert 0 <= c < n2
    if c not in memo:
        p.sendline(hex(c))
        memo[c] = bool(int(p.recvline()))
    return memo[c]

# find b
i = 512 + 3
while oracle(ciphertext) == oracle(ciphertext * encrypt(1 << i, 1) % n2):
    i -= 1
b = i
log.info('b = %d', b)

# offset
oracle_ciphertext = oracle(ciphertext)
if oracle_ciphertext:
    ciphertext *= encrypt(- 1 << b, 1)

# mc
i = 1023
mc = ''
while i >= 0:
    pad = (int(complement(mc) + '1', 2) << i)
    bit = (int(oracle(ciphertext) != oracle(ciphertext * encrypt(pad, 1) % n2)))
    mc += str(bit)
    log.info('i = %d: mc = %s', i, mc)
    i -= 1

# m
m = (- (int(complement(mc), 2) + 1 - (1 << b))) % n
if oracle_ciphertext:
    m += 1 << b
log.info('m = %d', m)

# flag
oracle(ciphertext * encrypt(- m, 1), memo={})
flag = 'TWCTF{' + sha1(str(m).encode('ascii')).hexdigest() + '}'
log.info('flag = %s', flag)
```

---

# Tokyo Westerns CTF 3rd 2017: BabyPinhole

-   2017年  9月 11日 月曜日 21:50:55 JST
    -   怪しい部分を修正
