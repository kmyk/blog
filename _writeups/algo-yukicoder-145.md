---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/145/
  - /blog/2016/12/29/yuki-145/
date: "2016-12-29T23:39:19+09:00"
tags: [ "competitive", "writeup", "yukicoder", "greedy" ]
"target_url": [ "http://yukicoder.me/problems/no/145" ]
---

# Yukicoder No.145 yukiover

簡単そうに見えて実装力が必要らしい。特にgolferが持つようなタイプのやつ。

## solution

貪欲。`yuki*`, `yuk*`, `yu*`, `y*`, `*`と長い順に作っていく。$O(N)$。

例えば`yu`まであるときに、他に$c \lt $`z`な$c$が存在せずかつ`z`があるとして、`yuz` $\gt$ `yuki`を作っても、`y` `u`を破棄して`z` $\gt$ `yuki`を作っても合計は変わらない。
`y` $\gt$ `u` $\gt$ `k` $\gt$ `i`であることも効いている。

## implementation

``` python
#!/usr/bin/env python3
import collections
# abcdefghijklmnopqrstuvwxyz
#         4 3         2   1
_ = int(input())
cnt = collections.Counter()
for c in input():
    cnt[c] += 1
def take(c, z=None):
    if z is None:
        z = c
    while c <= z:
        if cnt[c]:
            cnt[c] -= 1
            return c
        c = chr(ord(c) + 1)
    return ''
def construct(s):
    acc = ''
    for c in s:
        if c.islower():
            acc += take(c)
        elif c.isupper():
            acc += take(c.lower(), 'z')
    if len(acc) < len(s):
        for c in acc:
            cnt[c] += 1
        return False
    else:
        return True
ans = 0
for s in [ 'yukiA', 'yukJ', 'yuL', 'yV', 'Z' ]:
    while construct(s):
        ans += 1
print(ans)
```
