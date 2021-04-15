---
layout: post
redirect_from:
  - /writeup/ctf/2016/asis-ctf-finals-2016-secuprim/
  - /blog/2016/09/12/asis-ctf-finals-2016-secuprim/
date: "2016-09-12T02:26:22+09:00"
tags: [ "ctf", "writeup", "asis-ctf", "ppc" ]
---

# ASIS CTF Finals 2016: SecuPrim


$\mathrm{ans} = \mid\{ n \mid l \le n \le r \land (\mathrm{isprime}(n) \lor \exists m \lt n. \exists k. n = m^k ) \}\mid$.
This is done by simple implementation.

``` python
#!/usr/bin/env python2
import gmpy2
import string
import itertools
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='secuprim.asis-ctf.ir')
parser.add_argument('port', nargs='?', default=42738, type=int)
args = parser.parse_args()
context.log_level = 'debug'
p = remote(args.host, args.port)

# proof of work
p.recvuntil('ASIS needs proof of work to start the Math challenge.\n')
_, salt, _, prefix, _ = p.recvline().split('"')
prefix = prefix.rstrip('.')
log.info('salt: %s', salt)
log.info('prefix: %s', prefix)
letters = string.digits + string.ascii_uppercase + string.ascii_lowercase
try:
    for a in letters:
        for b in letters:
            for c in letters:
                for d in letters:
                    x = a + b + c + d
                    if hashlib.sha256(x + salt).hexdigest().startswith(prefix):
                        raise StopIteration
    log.error('Proof-of-Work Not Found')
except StopIteration:
    log.info('result: %s', x)
    p.sendline(x)

def is_valid(n):
    n = gmpy2.mpz(n)
    if gmpy2.is_prime(n):
        return True
    if bin(n).count('1') == 1:
        return True
    for k in itertools.count(2):
        root, rem = gmpy2.iroot_rem(n, k)
        if root == 2:
            return False
        if rem == 0:
            return True
while True:
    p.recvuntil("What's the number of primes or perfect powers like n such that: ")
    l, _, _, _, r = p.recvline().split()
    l, r = int(l), int(r)
    log.info('l: %d', l)
    log.info('r: %d', r)
    ans = 0
    for n in range(l, r+1):
        if is_valid(n):
            ans += 1
    log.info('result: %d', ans)
    p.send(str(ans))

p.recvall()
```
