---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2016-relay-d/
  - /blog/2016/11/30/code-festival-2016-relay-d/
date: "2016-11-30T01:33:22+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-relay-open/tasks/relay_d" ]
---

# CODE FESTIVAL 2016 Relay: D - 魔方陣2 / Magic Square 2

右上から左下へのななめの制約を忘れてWAした。

## solution

$$ \begin{pmatrix}
a & b & -a-b+3c \\\\
-2a-b+4c & c & 2a+b-2c \\\\
a+b-c & -b+2c & -a+2c
\end{pmatrix} $$

## implementation

``` python
#!/usr/bin/env python3
import itertools
a = int(input())
b = int(input())
c = int(input())
k = 3*c
f = [
        [             a,      b,     k-a-b ],
        [ 2*k-2*a-b-2*c,      c, 2*a+b+c-k ],
        [     a+b+2*c-k,  k-b-c,     k-a-c ] ]
assert f[0][2] + f[1][1] + f[2][0] == k
for y in range(3):
    print(*f[y])
```
