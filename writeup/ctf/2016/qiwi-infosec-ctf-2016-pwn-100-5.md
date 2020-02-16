---
layout: post
redirect_from:
  - /blog/2016/11/19/qiwi-infosec-ctf-2016-pwn-100-5/
date: "2016-11-19T01:31:21+09:00"
tags: [ "ctf", "writeup", "qiwi-ctf", "pwn", "rev", "go" ]
---

# Qiwi Infosec CTF 2016: PWN 100_5

strippedなgo binary(らしい)。admin用のコマンドを探せと言われて探すだけのrev問。出題ミス？

uppercase $4$文字なら$26^4 \approx 4.6 \times 10^5$と現実的なので総当たりすると見つかる。
本来のコマンドは分からないが、hash値の衝突により`DFNP`, `DNNX`, `DWNA`等複数存在する。
手元で叩くと`notrealofc`と言われるが、鯖へ持っていくと flag: `FLAG_YESYOUWIN_NYA:3`。

``` python
#!/usr/bin/env python2
import string
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='localhost')
parser.add_argument('port', nargs='?', default=3333, type=int)
args = parser.parse_args()

p = remote(args.host, args.port)
assert p.recvline().strip() == 'Welcome to pony info server, type `HELP` to list all available cmds'
def do(cmd):
    p.recvuntil('>')
    p.sendline(cmd)
    resp = p.recvline()
    if resp.strip() != 'unknown command':
        log.info('found: %s', cmd)
        log.info(resp)

for c1 in string.ascii_uppercase:
    for c2 in string.ascii_uppercase:
        for c3 in string.ascii_uppercase:
            for c4 in string.ascii_uppercase:
                do(c1 + c2 + c3 + c4)
                time.sleep(0.002)
            do(c1 + c2 + c3)
            time.sleep(0.02)
        do(c1 + c2)
        time.sleep(0.2)
        log.info('done: %c%c??', c1, c2)
    do(c1)
    time.sleep(0.2)
    log.info('done: %c???', c1)
```
