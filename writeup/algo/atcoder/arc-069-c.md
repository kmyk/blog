---
layout: post
redirect_from:
  - /blog/2018/01/05/arc-069-c/
date: "2018-01-05T23:34:39+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc069/tasks/arc069_a" ]
---

# AtCoder Regular Contest 069: C - Scc Puzzle

## solution

`Scc`を作れるだけ作り、次に`c`を$4$個まとめて`Scc`を作るのをやれるだけやる。$O(1)$。

## implementation

``` python
#!/usr/bin/env python3
s, c = map(int, input().split())
scc = min(s, c // 2)
cccc = (c - 2 * scc) // 4
print(scc + cccc)
```
