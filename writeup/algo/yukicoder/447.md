---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/447/
  - /blog/2016/11/19/yuki-447/
date: "2016-11-19T00:28:49+09:00"
tags: [ "copetitive", "writeup", "yukicoder", "implementation" ]
"target_url": [ "http://yukicoder.me/problems/no/446" ]
---

# Yukicoder No.447 ゆきこーだーの雨と雪 (2)

ちょっと重めの書くだけ。

## implementation

ドメインの色が濃いので競技ぽくないコードになった。変数名に迷わなくていいところは楽。

ACしてから見ると提出時間に小さい負数掛けて重みに足した部分だけ浮いている。普通にpairでsortしたい。

``` python
#!/usr/bin/env python3
import string
import collections
score = lambda n, k: 50*n + 250*n//(4+k)
n = int(input())
level = list(map(int, input().split()))
solved = [0]*n
leaderboard = collections.defaultdict(lambda: [0]*(n+1))
for t in range(int(input())):
    name, problem = input().split()
    i = string.ascii_uppercase.index(problem)
    solved[i] += 1
    leaderboard[name][i] = score(level[i], solved[i])
    leaderboard[name][-1] = - t*1e-8 # negative
leaderboard = list(leaderboard.items())
leaderboard.sort(key=lambda it: - sum(it[1]))
for i, it in enumerate(leaderboard):
    name, scores = it
    scores = scores[: -1] # drop column for AC time
    print(i+1, name, *scores, sum(scores))
```
