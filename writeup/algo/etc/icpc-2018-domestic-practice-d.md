---
layout: post
title: "ACM-ICPC 2018 模擬国内予選: D. 短歌数"
date: 2018-07-01T23:59:03+09:00
tags: [ "competitive", "writeup", "icpc-domestic", "dp", "digits-dp" ]
"target_url": [ "http://acm-icpc.aitea.net/index.php?2018%2FPractice%2F%E6%A8%A1%E6%93%AC%E5%9B%BD%E5%86%85%E4%BA%88%E9%81%B8%2F%E5%95%8F%E9%A1%8C%E6%96%87%E3%81%A8%E3%83%87%E3%83%BC%E3%82%BF%E3%82%BB%E3%83%83%E3%83%88" ]
---

## 解法

「長さ$K$の数列であって数列$p$をprefixとして持ちかつ短歌数であるようなものの数$f(K, p)$」が求められれば先頭から順に決めていける(典型)。たぶん$O(\log N)$とかだと思う。

初手$10$進数展開して数列を考える。
とりあえず長さを固定したいので「長さ$K$の数列であって短歌数なものの数」を考え、では次に$\dots$とやれば終了。

二分探索という話も聞こえてきたが実装が面倒なだけでやることは同じな気がする。

## 実装

``` python
#!/usr/bin/env python3
def count_tanka_numbers_of_length(k):
    binomial_9_2 = 9 * 8 // 2
    pattern = 2 ** k - 2
    pattern_with_0 = 2 ** (k - 1) - 1
    return binomial_9_2 * pattern + 9 * pattern_with_0

def count_tanka_numbers_of_length_k_with_prefix(k, prefix):
    kind = len(set(prefix)) 
    if kind == 0:
        return count_tanka_numbers_of_length(k)
    elif kind == 1:
        if 0 in prefix:
            return 0
        pattern = 2 ** (k - len(prefix)) - 1
        return 9 * pattern
    elif kind == 2:
        return 2 ** (k - len(prefix))
    else:
        return 0

def solve(n):
    n -= 1
    acc = 0
    k = 1
    while not (n < acc + count_tanka_numbers_of_length(k)):
        acc += count_tanka_numbers_of_length(k)
        k += 1
    prefix = []
    for _ in range(k):
        for d in range(10):
            if not (n < acc + count_tanka_numbers_of_length_k_with_prefix(k, prefix + [ d ])):
                acc += count_tanka_numbers_of_length_k_with_prefix(k, prefix + [ d ])
            else:
                prefix += [ d ]
                break
        else:
            assert False
    return ''.join(map(str, prefix))

while True:
    n = int(input())
    if n == 0:
        break
    print(solve(n))
```
