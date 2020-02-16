---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-078-e/
  - /blog/2017/07/15/arc-078-e/
date: "2017-07-15T23:15:37+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "reactive", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc078/tasks/arc078_c" ]
---

# AtCoder Regular Contest 078: E - Awkward Response

コーナーケース多い感じなどがなんだかICPCっぽい問題。
ガードレールにぶち当てながらアクセル全開にする感じのプログラミングするのやめたい (やめない)。

## solution

実験。judge側は自明なのでこれを書いて[いい感じのツール](https://github.com/kmyk/online-judge-tools)に食わせて手元でひたすら試す。

その結果得られるのが以下のアルゴリズム。$O(\log N)$。

-   まずはそのままの二分探索で$\mathrm{str}(N)$の先頭の数字を決定
    -   次で$k = 1$のときはここで得られた数字は嘘なので、最後のstepの前に空文字列のような扱いにしておく
-   次に$9, 99, 999, \dots$のようにして答えの桁数$k$を決定
    -   ただし先頭の数字が$9$ならば$1, 10, 100, 1000, \dots$とする
    -   $N = 1$のときは停止しないので、$k$が十分大きくなったら打ち切ってそう答える
-   最後に答えを構成。上の桁から順番に二分探索
    -   ただし最後の桁は別で、末尾に$0$を付ける必要がある。例えばそこまでが$3456$と判明してるときは$345650, 345680, 345690$などと試す。

## implementation

``` python
#!/usr/bin/env python3

def binsearch(l, r, pred): # [l, r)
    assert l < r
    l -= 1
    while r - l > 1:
        m = (l + r) // 2
        if pred(m):
            r = m
        else:
            l = m
    return r

import sys
def pred(n):
    assert 1 <= n and n <= 10 ** 18
    print('?', n)
    sys.stdout.flush()
    return input() == 'Y'

def solve():
    s = ''
    s += str(binsearch(1, 9 + 1, lambda c: not pred(int(s + str(c)))) - 1)

    if s == '9':
        f = lambda k: pred(int('1' + '0' * k))
    else:
        f = lambda k: not pred(int('9' * k))
    k = 1
    while f(k):
        k += 1
        if k >= 13:
            return 1
    if k == 1:
        s = ''

    for _ in range(k - 2):
        s += str(binsearch(0, 9 + 1, lambda c: not pred(int(s + str(c)))) - 1)
    s += str(binsearch(0, 9 + 1, lambda c: pred(int(s + str(c) + '0'))))

    return int(s)

print('!', solve())
```

### judge program

``` python
#!/usr/bin/env python3
import sys
import random

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('N', nargs='?', default=random.randint(1, 10 ** 9), type=int)
args = parser.parse_args()
y = args.N
print('[*] y =', y, file=sys.stderr)

for k in range(65):
    c, x = input().split()
    x = int(x)
    print('[*] %d-th query: %s %d' % (k, c, x), file=sys.stderr)
    assert 1 <= x <= 10 ** 18
    if c == '?':
        if (x <= y and str(x) <= str(y)) or (x > y and str(x) > str(y)):
            result = 'Y'
        else:
            result = 'N'
        print(result)
        sys.stdout.flush()
        print('[*] %d-th query: %s' % (k, result), file=sys.stderr)
    elif c == '!':
        assert y == x
        break
    else:
        assert False
    sys.stdout.flush()
```
