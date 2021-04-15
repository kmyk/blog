---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_081_c/
  - /writeup/algo/atcoder/arc-081-c/
  - /blog/2017/08/21/arc-081-c/
date: "2017-08-21T00:12:14+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc081/tasks/arc081_a" ]
---

# AtCoder Regular Contest 081: C - Make a Rectangle

## solution

ふたつ以上ある数で最も大きいもの、そのふたつを除いての最も大きいものを取ってきてその積。
$O(N \log N)$でsortしていい感じにする。

`unordered_map`するか`stack`でいい感じにやると$O(N)$だが不要。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
a = list(map(int, input().split()))
a.sort()
b = [ 0, 0 ]
i = 0
while i + 1 < n:
    if a[i] == a[i + 1]:
        b += [ a[i] ]
        i += 2
    else:
        i += 1
print(b[-2] * b[-1])
```
