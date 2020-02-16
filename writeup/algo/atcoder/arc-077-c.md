---
layout: post
redirect_from:
  - /blog/2017/07/20/arc-077-c/
date: "2017-07-20T03:11:56+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc077/tasks/arc077_a" ]
---

# AtCoder Regular Contest 077: C - pushpush

Pythonのversion違いでREになった。3.4.3をやめろ、あるいは最初にサンプルで実行してREやWAでもペナルティなし機能とか欲しい。

## solution

例えば$a = (1, 2, 3, 4, 5, \dots)$という数列を考えると、$b = (), (1 ), (2, 1), (3, 1, 2), (4, 2, 1, 3), (5, 3, 1, 2, 4), \dots$と続く。
反転を無視すれば先頭と末尾に交互に追加している。

## implementation

`collections.deque`でよかったのではという気持ち。

``` python
#!/usr/bin/env python3
n = int(input())
a = input().split()
l = []
r = []
for a_i in a:
    r += [ a_i ]
    l, r = r, l
print(*(list(reversed(l)) + r))
```
