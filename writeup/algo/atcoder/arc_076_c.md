---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-076-c/
  - /blog/2017/12/31/arc-076-c/
date: "2017-12-31T20:37:14+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc076/tasks/arc076_a" ]
---

# AtCoder Regular Contest 076: C - Reconciled?

## solution

犬と猿が交互に来るしかない。それぞれの数の差の絶対値が$2$以上なら$0$。$1$以下なら階乗を掛け合わせる感じで。$O(N + M)$。

## implementation

``` python
#!/usr/bin/env python3
import array
def get_fact(n, mod):
    fact = array.array('l')
    fact.append(1)
    for i in range(n):
        fact.append((i + 1) * fact[-1] % mod)
    return fact

mod = 10 ** 9 + 7
n, m = map(int, input().split())
fact = get_fact(max(n, m), mod)
if n == m:
    result = (fact[n] * fact[m]) * 2
elif abs(n - m) == 1:
    result = fact[n] * fact[m]
else:
    result = 0
print(result % mod)
```
