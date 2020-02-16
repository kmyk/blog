---
layout: post
redirect_from:
  - /blog/2018/04/07/arc-094-c/
date: "2018-04-07T23:01:42+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc094/tasks/arc094_a" ]
---

# AtCoder Regular Contest 094: C - Same Integers

## solution

貪欲。$O(1)$で書ける。

$A \le B \le C$と仮定する。
$2$種類の操作は共に$A, B, C$を減少させることはなくまた$A + B + C$を$2$増やす。
操作の開始前の$C = C\_0$を使って$A = B = C = C\_0$が達成できればそれが答えであり、それができないなら$A = B = C = C\_0 + 1$の場合が答え。
まず$A + 2, B + 2 \le C$の間$A, B$に$2$加える。
その後$A \le B \le C$であるように取り直すと$A = B = C = C\_0$または$A = C\_0 - 1 \land B = C = C\_0$または$A = B = C\_0 - 1 \land C = C\_0$である。
$A = C\_0 - 1 \land B = C = C\_0$の場合に$A = B = C = C\_0$が達成不能なのは$A + B$の偶奇から言える。
よってこの貪欲は妥当。

## note

-   未証明のまま貪欲を投げました

## implementation

``` python
#!/usr/bin/env python3
a, b, c = map(int, input().split())
answer = 0
while not (a == b == c):
    a, b, c = sorted([ a, b, c ])
    if a + 2 <= c:
        a += 2
    else:
        a += 1
        b += 1
    answer += 1
print(answer)
```
