---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/488/
  - /blog/2017/02/24/yuki-488/
date: "2017-02-24T23:57:31+09:00"
tags: [ "competitive", "writeup", "yukicoder", "graph" ]
"target_url": [ "https://yukicoder.me/problems/no/488" ]
---

# Yukicoder No.488 四角関係

golfしようと思ってそのままpythonで書いたやつを削ったら定数倍が重くなっててTLEした。

## solution

全探索。$O(N^4)$。

重複して数えないこと、条件を満たす$4$つの頂点$(i,j,k,l)$は必ずしも$i \lt j \lt k \lt l$ではないことに注意する。

## implementation

``` python
#!/usr/bin/env python3
n, m = map(int, input().split())
g = [ [ False for _ in range(n) ] for _ in range(n) ]
for _ in range(m):
    a, b = map(int, input().split())
    a -= 1
    b -= 1
    g[a][b] = g[b][a] = True
cnt = 0
for a in range(n):
    for b in range(a):
        for c in range(b):
            for d in range(c):
                for i, j, k, l in [ (a,b,c,d), (a,c,b,d), (a,c,d,b) ]:
                    if g[i][j] and g[j][k] and g[k][l] and g[l][i] and not g[i][k] and not g[j][l]:
                        cnt += 1
print(cnt)
```
