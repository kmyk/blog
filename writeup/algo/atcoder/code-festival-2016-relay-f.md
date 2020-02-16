---
layout: post
redirect_from:
  - /blog/2016/11/30/code-festival-2016-relay-f/
date: "2016-11-30T01:33:26+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-relay-open/tasks/relay_f" ]
---

# CODE FESTIVAL 2016 Relay: F - 3分割ゲーム / Trichotomy

これぐらいなら十分にgolfしてもいいと思うんだけど、それならanagol行くしなあという気がして手が出ない。

## solution

まず$f(N)$について。$N = 1 + \lfloor \frac{1}{N} \rfloor + \lceil \frac{1}{N} \rceil$と分割するのが最良で$f(N) = 1 + f(\lfloor \frac{1}{N} \rfloor)$となる。これを二分探索すればよい。あるいは逆っぽい関数を書けば$O(X)$で済む。

## implementation

``` python
#!/usr/bin/env python3
def g(x):
    if x == 0:
        return 1
    else:
        return 1 + g(x-1) * 2
x = int(input())
print(g(x+1)-1)
```
