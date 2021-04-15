---
layout: post
redirect_from:
  - /writeup/ctf/2017/code-blue-ctf-2017-paillier-oracle/
  - /blog/2017/12/08/code-blue-ctf-2017-paillier-oracle/
date: "2017-12-08T21:22:25+09:00"
tags: [ "ctf", "writeup", "crypto", "code-blue-ctf", "paillier-cryptosystem", "decryption-oracle", "hardcore-bit", "homomorphic-property" ]
"target_url": [ "https://ctftime.org/task/4876" ]
---

# CODE BLUE CTF 2017: Paillier Oracle

[editorial](https://shiho-elliptic.tumblr.com/post/168216679824/my-authored-challenges-at-code-blue-ctf-2017)にNoteとして書かれている部分に悲しみがただよっていた。

前回は$b$-bit目より上は深くは理解せず雑にやったが今回はもう少しまじめに解いた。

## solution

[Tokyo Westerns CTF 3rd 2017: BabyPinhole](https://ctftime.org/task/4564)で[やった](https://kimiyuki.net/blog/2017/09/04/twctf-2017-babypinhole/)のと同じことをすればよい。

今回のhardcore bitは$0$-bit目。
つまり、準同型性を使って、$\mathrm{oracle}(c \cdot \mathrm{enc}(\delta))$として$(c + \delta) \bmod n$のLSBが得られる。
$-1$-bit目(つまり$2047$-bit目)から順に決めていくことになる。

$0 \lt k \le \lceil \log m \rceil$として$\mathrm{lsb}((m - 2^k) \bmod n)$の値を考えよう。
$m - 2^k \ge 0$なら$\mathrm{lsb}((m - 2^k) \bmod n) = \mathrm{lsb}(m - 2^k) = \mathrm{lsb}(m)$と不変。
$m - 2^k \lt 0$なら$\mathrm{lsb}((m - 2^k) \bmod n) = \mathrm{lsb}(m - 2^k + n) = \mathrm{lsb}(m + n)$であり、$n = pq$により$n$は奇数なので$\ne \mathrm{lsb}(m)$。
ただしそのままだと$m - 2^k \lt 0$となるのは$k \gt \log m$の場合の$1$回のみである。
そこで$m$の$k$-bit目より上の部分(つまり$m$のそれまでに判明している部分)を$\bar{m}$として$\mathrm{lsb}((m - \bar{m} - 2^k) \bmod n)$とする。
これらにより、$m$の$k$-bit目が$1$なら繰り下がりなし、$0$ならありでLSBが変化するようにでき、全て求まる。

## implementation

``` c++
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='localhost')
parser.add_argument('port', nargs='?', default=7485, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level
p = remote(args.host, args.port)

# proof of work
import hashlib
import itertools
import re
s = p.recvline()
suffix, target = re.match(r'^SHA256\(XXXX\+([0-9A-Za-z]+)\) == ([0-9a-z]+)\n$', s).groups()
log.info('now proving...')
for xxxx in itertools.permutations(string.ascii_letters + string.digits, r=4):
    xxxx = ''.join(xxxx)
    if hashlib.sha256(xxxx + suffix).hexdigest() == target:
        log.info('found')
        p.sendlineafter('What is XXXX? ', xxxx)
        break

# input
import ast
p.recvuntil('Public key is here: ')
n, g = ast.literal_eval(p.recvline())
p.recvuntil('...and Encrypted Flag: ')
c = int(p.recvline())
log.info('n = %d', n)
log.info('g = %d', g)
log.info('c = %d', c)

def oracle(c):
    p.sendlineafter('Your ciphertext here: ', str(c))
    p.recvuntil('LSB is ')
    return int(p.recvline())

import gmpy2
def encrypt(m):
    assert m < n
    while True:
        r = randint(1, n)
        if gmpy2.gcd(r, n) == 1:
            break
    c1 = pow(g, m, n ** 2)
    c2 = pow(r, n, n ** 2)
    return (c1 * c2) % n ** 2

# attack
original_lsb = oracle(c)
m = 0
for i in reversed(range(2048)):
    lsb = oracle(c * encrypt((- m - 2 ** i) % n) % n ** 2)
    if lsb == original_lsb:
        m += 2 ** i
    log.info(bin(m))

# output
from Crypto.Util.number import long_to_bytes
log.info('m = %s', long_to_bytes(m))
```
