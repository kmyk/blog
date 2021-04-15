---
layout: post
redirect_from:
  - /writeup/ctf/2016/csaw-quals-2016-coinslot/
  - /blog/2016/09/19/csaw-quals-2016-coinslot/
date: "2016-09-19T22:08:49+09:00"
tags: [ "ctf", "writeup", "csaw-ctf", "misc" ]
---

# CSAW Quals CTF 2016: Coinslot

金額を紙幣/硬貨で分解するやつ。
実装するだけで面白くないし解かなくてもよくない？みたいな気分はあったが、すぐなので解いておいた。

与えられた正規表現にmatchする文字列を返せというRegexpireという似た問題があり同様の判断を下していたが、これはそういうのしてくれるmoduleが使いやすい形である([rstr](https://pypi.python.org/pypi/rstr), [String::Random](http://search.cpan.org/~shlomif/String-Random/), etc)らしいので誤判断だった。
あるだろうというのはそうなので軽く検索したが見つけられなかったんだよね。

``` python
#!/usr/bin/env python2
import itertools
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='misc.chal.csaw.io')
parser.add_argument('port', nargs='?', default=8000, type=int)
args = parser.parse_args()
context.log_level = 'debug'

p = remote(args.host, args.port)
for i in itertools.count(1):
    y = int(round(float(p.recvline().lstrip('$')) * 100))
    log.info('%d-th iteration: $%d.%d', i, y/100, y%100)
    for s in [
            '$10,000 bills: ',
            '$5,000 bills: ',
            '$1,000 bills: ',
            '$500 bills: ',
            '$100 bills: ',
            '$50 bills: ',
            '$20 bills: ',
            '$10 bills: ',
            '$5 bills: ',
            '$1 bills: ',
            'half-dollars (50c): ',
            'quarters (25c): ',
            'dimes (10c): ',
            'nickels (5c): ',
            'pennies (1c): ', ]:
        p.recvuntil(s)
        if s.startswith('$'):
            x = 100 * int(s.replace(',', '').strip('$ bills:'))
        else:
            x = int(s.split('(')[1].split('c)')[0])
        p.sendline(str(y / x))
        y %= x
    assert y == 0
    if p.recvline().strip() != 'correct!':
        break
    raise
p.recvall()
```
