---
layout: post
redirect_from:
  - /writeup/algo/csacademy/41-d/
  - /writeup/algo/cs-academy/41-d/
  - /blog/2017/08/10/csa-41-d/
date: "2017-08-10T02:31:04+09:00"
tags: [ "competitive", "writeup", "csacademy", "construction", "graph", "bfs", "dfs" ]
"target_url": [ "https://csacademy.com/contest/round-41/task/bfs-dfs/" ]
---

# CS Academy Round #41: D. BFS-DFS

発想。

## problem

BFSをしたときの頂点列とDFSをしたときの頂点列が通り掛け順で見て与えられるので、そのようになるグラフをひとつ出力せよ。
ただし辺の出力順によってBFS/DFSの結果は変化することに注意。

## solution

ほとんど車輪なものを作る。
始点とその次の頂点は一致していないとおかしいので、そうだとする。
DFSの順に$1$本の道を張り、その後にBFSの順に始点から辺を張ればよい。
$O(N)$。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
bfs = list(map(int, input().split()))
dfs = list(map(int, input().split()))
if bfs[: 2] != dfs[: 2]:
    print(-1)
else:
    print(2 * n - 3)
    for i in range(n - 1):
        print(dfs[i], dfs[i + 1])
    for i in range(2, n):
        print(bfs[0], bfs[i])
```
