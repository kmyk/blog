---
layout: post
redirect_from:
  - /writeup/algo/csacademy/41-b/
  - /writeup/algo/cs-academy/41-b/
  - /blog/2017/08/10/csa-41-b/
date: "2017-08-10T02:31:00+09:00"
tags: [ "competitive", "writeup", "csacademy" ]
"target_url": [ "https://csacademy.com/contest/round-41/task/cinema-seats/" ]
---

# CS Academy Round #41: B. Cinema Seats

微妙に面倒。さらにコーナー。

## problem

`0` `1`の列が与えられる。高々$1$回のswapをして、連続する`0`の数を最大化せよ。

## solution

`0` の列が間にちょうどひとつの`1`を挟んで隣接しているなら併合できる。
そんな感じで探す。ただし`000001`や`111001000111`のような`1`を飛ばす先が足りてないケースに注意する。
$O(N)$。

## implementation

``` c++
#!/usr/bin/env python3
def solve(s):
    result = 0
    last_l, last_r = (-3, -2)
    l = 0
    while l < len(s):
        while l < len(s) and s[l] == '1':
            l += 1
        if l == len(s):
            break
        r = l + 1
        while r < len(s) and s[r] == '0':
            r += 1
        result = max(result, r - l + 1)
        if last_r + 1 == l:
            result = max(result, r - last_l)
        last_l, last_r = (l, r)
        l = r
    result = min(s.count('0'), result)
    return result
print(solve(input()))
```
