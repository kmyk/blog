---
layout: post
alias: "/blog/2017/09/04/twctf-2017-babydlp/"
date: "2017-09-04T16:40:40+09:00"
tags: [ "ctf", "writeup", "twctf", "crypto", "dlp" ]
---

# Tokyo Westerns CTF 3rd 2017: BabyDLP

寝てる間にkonjoさんが解いてくれました。

## problem

素数$p$と整数$g$および暗号化oracle $\mathrm{oracle}(s) = c \equiv g^{m \oplus s} \pmod{p}$が与えられる。$m$を答えよ。

## solution

$\mathrm{oracle}(2^k)$を考えると$m$の$k$-bit目に対応して$\mathrm{oracle}(0) \cdot g^{\pm 2^k}$。
これをそれぞれの$k$で試せば終わり。

$g = 2$でなくても解ける。
`line = fin.readline()[:4+bits//4]`は今回は何も邪魔をしない。$m$のbit数より小さい制約だと問題になる。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='ppc2.chal.ctf.westerns.tokyo')
parser.add_argument('port', nargs='?', default=28459, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level

# params
p = 160634950613302858781995506902938412625377360249559915379491492274326359260806831823821711441204122060415286351711411013883400510041411782176467940678464161205204391247137689678794367049197824119717278923753940984084059450704378828123780678883777306239500480793044460796256306557893061457956479624163771194201
g = 2
bits = 1024

# connect
proc = remote(args.host, args.port)
def oracle(s):
    line = hex(s)[2 :]
    assert line == line[: 4 + bits // 4]
    proc.sendline(line)
    c = int(proc.recvline(), 16)  # c = pow(g, m ^ s, p)
    return c

# run
c0 = oracle(0)
m = 0
i = 1
while i <= p:
    ci = oracle(i)
    if c0 == ci * pow(g, i, p) % p:
        m |= i
    else:
        assert ci == c0 * pow(g, i, p) % p
    log.info('m = %#x', m)
    i <<= 1

# result
log.info('flag = %s', hex(m)[2 :].decode('hex'))
```
