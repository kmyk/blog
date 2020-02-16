---
layout: post
date: 2018-07-01T23:59:01+09:00
tags: [ "competitive", "writeup", "icpc-domestic" ]
"target_url": [ "http://acm-icpc.aitea.net/index.php?2018%2FPractice%2F%E6%A8%A1%E6%93%AC%E5%9B%BD%E5%86%85%E4%BA%88%E9%81%B8%2F%E5%95%8F%E9%A1%8C%E6%96%87%E3%81%A8%E3%83%87%E3%83%BC%E3%82%BF%E3%82%BB%E3%83%83%E3%83%88" ]
---

# ACM-ICPC 2018 模擬国内予選: B. 一般化うるう年

## note

これは特に言うことなし。 `is_uruu` はそうなんだけど自制した。

## 実装

``` python
#!/usr/bin/env python3

def is_leap(n, a, x):
    i = 0
    while i < n and x % a[i] != 0:
        i += 1
    return i % 2 == 0

while True:
    n, l, r = map(int, input().split())
    if n == l == r == 0:
        break
    a = [ int(input()) for _ in range(n) ]
    answer = 0
    for x in range(l, r + 1):
        answer += is_leap(n, a, x)
    print(answer)
```
