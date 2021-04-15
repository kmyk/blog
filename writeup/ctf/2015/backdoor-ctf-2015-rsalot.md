---
layout: post
redirect_from:
  - /writeup/ctf/2015/backdoor-ctf-2015-rsalot/
  - /blog/2016/08/31/backdoor-ctf-2015-rsalot/
date: "2016-08-31T18:51:05+09:00"
tags: [ "ctf", "writeup", "crypto", "backdoor-ctf", "rsa", "oaep" ]
"target_url": [ "https://github.com/ctfs/write-ups-2015/tree/master/backdoor-ctf-2015/crypto/rsalot" ]
---

# backdoor CTF 2015: RSALOT

解けず。gcdは何度も見てるので分かるが、OAEPは思い出せず。

## solution

RSA問。
公開鍵がたくさん与えられるので、gcdを取れば秘密鍵を取り、OAEPでもって複合化すればよい。

`the_flag_is_b767b9d1fe02eb1825de32c6dacf4c2ef78c738ab0c498013347f4ea1e95e8fa`

``` python
#!/usr/bin/env python3
import math
import base64
import gmpy2
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
d = lambda p, q, e: int(gmpy2.invert(e, (p-1)*(q-1)))

# load public keys
e = 0x10001
pubkeys = []
for i in range(100):
    with open('%d.pem' % (i+1)) as fh:
        key = RSA.importKey(fh.read())
    assert key.e == e
    pubkeys.append(key)

# construct private keys using gcd
keys = {}
for j, b in enumerate(pubkeys):
    for i, a in enumerate(pubkeys[: j]):
        p = math.gcd(a.n, b.n)
        if p != 1:
            for k in [ i, j ]:
                n = pubkeys[k].n
                keys[k] = RSA.construct((n, e, d(p, n//p, e)))

# load encrypted string
with open('flag.enc') as fh:
    c = base64.b64decode(fh.read())

# decrypt it
for i, key in keys.items():
    key = PKCS1_OAEP.new(key)
    try:
        m = key.decrypt(c)
        print(m.decode())
    except ValueError:
        pass
```
