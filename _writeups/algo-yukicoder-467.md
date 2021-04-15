---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/467/
  - /blog/2016/12/20/yuki-467/
date: "2016-12-20T00:09:28+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/467" ]
---

# Yukicoder No.467 隠されていたゲーム

始め見たときは面倒そうでつらいと思ったが、よく考えたらそうではなかったのでやられたという気持ち。

## solution

ちょうどChebyshev距離$d$しか移動できないとしても、$2$回の移動で$2d$以内の好きな位置へ移動できる。
これにより、遠くへ移動する場合は$\lceil \frac{\max \\{ \|x\|, \|y\| \\}}{\max_i d_i} \rceil$が答え。近くの場合は丁寧に。
$O(1)$。

## implementation

原点の処理や絶対値の取り忘れに注意。

``` python
#!/usr/bin/env python3
n = int(input())
d = list(map(int, input().split()))
x, y = map(int, input().split())
x, y = abs(x), abs(y)
if x == y == 0:
    ans = 0
elif max(x, y) in d:
    ans = 1
elif max(x, y) < max(d):
    ans = 2
else:
    ans = (max(x, y) + max(d)-1) // max(d)
print(ans)
```
