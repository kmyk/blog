---
layout: post
redirect_from:
  - /writeup/algo/etc/gcj-2016-round1a-b/
  - /blog/2016/04/16/gcj-2016-round1a-b/
date: 2016-04-16T15:23:50+09:00
tags: [ "competitive", "writeup", "gcj", "google-code-jam", "parity", "frequency" ]
"target_url": [ "https://code.google.com/codejam/contest/4304486/dashboard#s=p1" ]
---

# Google Code Jam 2016 Round 1A B. Rank and File

I couldn't realize the parity, and solved only the small.

## problem

全ての行と列が狭義単調増加な$N$次正方行列があった。
この行列の行と列を列挙し、そこからどれかひとつを削除したもの($2N-1$個の$N$次元vector)が与えられる。
削除されたvectorを復元し答えよ。

## solution

parity. frequency. $O(N \times N)$, linear time for the number of elements of the matrix.

Count the frequency of integers in the given vectors.
Almost all integers are counted twice, in the row vector and in the column vector.
But integers in the removed vector are counted twice.
So you should collect the integers which appears odd-times.


## implementation

``` python
#!/usr/bin/env python3
for t in range(int(input())):
    n = int(input())
    cnt = {}
    for y in range(2*n-1):
        xs = list(map(int,input().split()))
        for x in xs:
            cnt[x] = (x in cnt and cnt[x] or 0) + 1
    ans = []
    for x in cnt:
        if cnt[x] % 2 == 1:
            ans.append(x)
    ans.sort()
    print('Case #{}: {}'.format(t+1, ' '.join(map(str,ans))))
```
