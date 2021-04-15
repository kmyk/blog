---
layout: post
redirect_from:
  - /writeup/ctf/2017/polictf-2017-lucky-consecutive-guessing/
  - /blog/2017/07/10/polictf-2017-lucky-consecutive-guessing/
date: "2017-07-10T00:10:11+09:00"
tags: [ "ctf", "writeup", "polictf", "crypto", "linear-congruential-generator", "prng" ]
"target_url": [ "https://scoreboard.polictf.it" ]
---

# polictf 2017: Lucky Consecutive Guessing

しほさんがURLを置いてくれていたので実装するだけだった。
他のcryptoやguessingは解けずだったのでやったのはこれだけ。
ところで私もプロとカラオケでCTFするやつやりたい。

そういえば大きい数で割って変数を消すのはWiener's Attackでも見た気がする。よくある手法なのか。

## problem

```
$ nc lucky.chall.polictf.it 31337
Welcome!
Do you feel lucky? Try to guess the numbers I'm thinking of.
You have one minute to reach 100 points. Good Luck!
You have 10 points.
Guess the next number:
42
Wrong, the correct number was 2914548618.
You have 9 points.
Guess the next number:

```

定数が既知の線形合同法による出力の列が与えられる。
ただし出力として与えられるのは上位bitのみ。
ここから状態を復元する問題。

## solution

Read this: <https://crypto.stackexchange.com/questions/10608/how-to-attack-a-fixed-lcg-with-partial-output>.

内部状態が$\mathrm{nbits}$bitあり生成式$X' = (aX + b) \bmod 2^{\mathrm{nbits}}$、その内で観測できるのが$\mathrm{output}$bitであったとする。
このとき$\mathrm{hidden} = \mathrm{nbits} - \mathrm{output}$に対し$a \gt 2^{\mathrm{hidden}}$であれば、この$a$で諸々を割ることで秘匿されている部分の値を式から消去してやれるよね、というのが概要。

## implementation

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='lucky.chall.polictf.it')
parser.add_argument('port', nargs='?', default=31337, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level
p = remote(args.host, args.port)

a = 0x66e158441b6995
b = 0xB
nbits = 85
output = 32
hidden = nbits - output

# https://crypto.stackexchange.com/questions/10608/how-to-attack-a-fixed-lcg-with-partial-output
assert a >= 2 ** hidden
r = []
for i in range(9):
    p.recvuntil('Guess the next number:')
    p.sendline('0')
    p.recvuntil('Wrong, the correct number was ')
    number = int(p.recvline().rstrip().rstrip('.'))
    r += [ number ]
    log.info('output %d: %d', i, number)
r0 = r[0]
r1 = r[1]
t = ((r1 - a * r0 + 1) * 2 ** hidden - b - 1) % (2 ** nbits)
for k in range((a * 2 ** hidden - 1 - t) // (2 ** nbits) + 1):
    if (t + k * 2 ** nbits) % a < 2 ** hidden:
        x0 = (t + k * 2 ** nbits) // a + r0 * 2 ** hidden
        x = x0
        for i in range(9):
            if x >> hidden != r[i]:
                break
            x = (a * x + b) % (2 ** nbits)
        else:
            break
log.info('found: %d', x0)

x = x0
for _ in range(9):
    x = (a * x + b) % (2 ** nbits)
    log.info('%d : %d', x, x >> hidden)
while True:
    p.recvuntil('Guess the next number:')
    p.sendline(str(x >> hidden))
    x = (a * x + b) % (2 ** nbits)
```
