---
layout: post
redirect_from:
  - /writeup/algo/atcoder/ddcc-2016-final-b/
  - /blog/2016/12/03/ddcc-2016-final-b/
date: "2016-12-03T14:31:47+09:00"
tags: [ "competitive", "writeup", "atcoder", "ddcc" ]
"target_url": [ "https://beta.atcoder.jp/contests/ddcc2016-final/tasks/ddcc_2016_final_b" ]
---

# DISCO presents ディスカバリーチャンネル コードコンテスト2016 本戦: B - デュアルカット

## solution

中央付近は$i$番と$i+M$番目の$M$組をいい感じに切り、それ以外は$i$番と$j = N-i$番というように対称に切っていく。
$O(N)$。

$i$番目と$j = N-i$番という形で同じ長さの組で切り続けるのが(可能なら)最適である。
偶数個の分割で真ん中の一番長い部分を単独で切断することになる場合でもそう。
しかし中央付近はこのようには切れないので、貪欲っぽく修正する。

## implementation

整理すれば単一の数式に落とせるような気がする。

``` python
#!/usr/bin/env python3
import math
r, n, m = map(int, input().split())

data = [ False ] * (n-1)
def setcut(i):
    if 1 <= i <= n-1:
        data[i-1] = True
def is_cut(i):
    if 1 <= i <= n-1:
        return data[i-1]
    else:
        return True
def cutlen(i):
    if 1 <= i <= n-1:
        sin = 2*abs(i/n - 0.5)
        return r * 2*math.sqrt(1 - sin**2)
    else:
        return 0

acc = 0
for delta in range(m):
    i = n//2 - delta
    if not is_cut(i) or not is_cut(i+m):
        setcut(i)
        setcut(i+m)
        acc += max(cutlen(i), cutlen(i+m))
for i in range(1,n-1):
    if not is_cut(i) or not is_cut(n-i):
        setcut(i)
        setcut(n-i)
        acc += max(cutlen(i), cutlen(n-i))

print(acc)
```
