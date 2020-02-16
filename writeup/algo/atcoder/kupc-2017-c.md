---
layout: post
redirect_from:
  - /blog/2017/10/22/kupc-2017-c/
date: "2017-10-22T13:33:24+09:00"
tags: [ "competitive", "writeup", "kupc", "atcoder", "multiprecision" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2017/tasks/kupc2017_c" ]
---

# Kyoto University Programming Contest 2017: C - Best Password

hash値を持つのは正しい行いですが、可能ならsaltも付けたほうがよいですね。

## solution

多倍長整数で上の桁から貪欲。$O(\|S\|)$。

rolling hash風の多項式hash。剰余を取っているとLLLなどが必要になるだろうが、$\mathbb{N}$の上で計算しているので不要。
まず$H(S)$を越えるまで`z`を足して`zzz...z`のような文字列を作る。
そして辞書順最大であるので、$H(S)$に一致するよう`zzz...zy` `zzz...zx` `zzz...zw` $\dots$ `zzz...zyz` `zzz...zyy` $\dots$ と減らしていく。$A \le 10$なのでこれは目的の文字列を見付ける。


## implementation

``` python
#!/usr/bin/env python3
import string
def c(s_i):
    return ord(s_i) - ord('a') + 1
def encode(a, s):
    acc = 0
    for s_i in reversed(s):
        acc += c(s_i)
        acc *= a
    return acc
def decode(a, k):
    s = [ ]
    acc = 0
    e = 1
    while acc < k:
        s += 'z'
        e *= a
        acc += e * c('z')
    for i in reversed(range(len(s))):
        acc -= e * c('z')
        for s_i in string.ascii_lowercase:
            if k <= acc + e * c(s_i):
                acc += e * c(s_i)
                s[i] = s_i
                break
        e //= a
        if acc == k:
            break
    return ''.join(s)

a = int(input())
s = input()
print(decode(a, encode(a, s)))
```
