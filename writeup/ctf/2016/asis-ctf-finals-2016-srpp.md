---
layout: post
alias: "/blog/2016/09/12/asis-ctf-finals-2016-srpp/"
date: "2016-09-12T02:27:08+09:00"
tags: [ "ctf", "writeup", "asis-ctf", "crypto" ]
---

# ASIS CTF Finals 2016: SRPP

SRPP is an abbreviation of <https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol>.

To solve this, let $A = 2N \equiv 0 \pmod N$.
The server checks that $A \ne 0 \land A \ne N$, but this is not perfect.
And $A \equiv 0$ makes things trivial.

``` python
#!/usr/bin/env python2
import hashlib
import string
import itertools
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='srpp.asis-ctf.ir')
parser.add_argument('port', nargs='?', default=22778, type=int)
args = parser.parse_args()
context.log_level = 'debug'
p = remote(args.host, args.port)

# proof of work
p.recvuntil('ASIS needs proof of work to start the SRPP challenge.\n')
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
                    if hashlib.sha512(x + salt).hexdigest().startswith(prefix):
                        raise StopIteration
    log.error('Proof-of-Work Not Found')
except StopIteration:
    log.info('result: %s', x)
    p.sendline(x)

def Hash(*args):
    a = ':'.join(str(a) for a in args)
    return int(hashlib.sha256(a).hexdigest(), 16)

p.recvuntil('(N, g, k) = ')
N, g, k = map(lambda s: int(s.strip('(L,)')), p.recvline().split())
log.info('N: %d', N)
log.info('g: %d', g)
log.info('k: %d', k)
assert k == Hash(N, g)

p.recvuntil('Send the email address and the public random positive value A seperated by "," as "email, A": ')
email = 'admin@asis-ctf.ir'
A = 2*N
log.info('email: %d', email)
log.info('A: %d', A)
p.sendline('%s, %d' % (email, A))

p.recvuntil('(salt,  public_ephemeral) = ')
salt, B = p.recvline().split()
salt = salt.strip('(L,)').decode('base64')
B = int(B.strip('(L,)'))
log.info('salt: %s', repr(salt))
log.info('B: %d', B)

u = Hash(A, B)
log.info('u: %d', u)

p.recvuntil('Send the session key: \n')
S_s = 0
K_client = Hash(S_s)
p.sendline(str(K_client))

p.recvuntil('Send a POC of session key: \n')
M_client = Hash(Hash(N) ^ Hash(g), Hash(email), salt, A, B, K_client)
p.sendline(str(M_client))

p.recvall()
```
