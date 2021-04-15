---
redirect_from:
layout: post
date: 2018-10-01T01:14:43+09:00
tags: [ "competitive", "writeup", "atcoder", "kupc", "puzzle", "construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2018/tasks/kupc2018_c" ]
---

# Kyoto University Programming Contest 2018: C - 七目

## 解法

### 概要

満点が取れると仮定して必要条件を列挙し適当に構成する。$O(1)$

### 詳細

$200$点を取れると仮定すると:

-   `#` は11個
-   各行/各列に最低ひとつは `#` が必要
-   端付近の行/列に置いた場合は向かい側にも必要

ここから周囲は下の形がそれっぽいと分かる。
さらに中央付近を適当に埋めてみると正解が見付かる。

```
......#..
..#......
#......#.
.........
.........
.........
.#......#
......#..
..#......
```

## 実装

``` python
#!/usr/bin/env python3
N = 9
K = 7
def get_score(f):
    for y in range(N):
        for x in range(N):
            for i in range(4):
                dy = [ 0, 1, 1,  1 ][i]
                dx = [ 1, 1, 0, -1 ][i]
                for k in range(7):
                    ny = y + k * dy
                    nx = x + k * dx
                    if not (0 <= ny < N and 0 <= nx < N):
                        break
                    if f[ny][nx] == '#':
                        break
                else:
                    return -1
    n = ''.join(f).count('#')
    return 200 // max(1, n - 10)

f = '''
......#..
..#......
#......#.
...#.....
....#....
.....#...
.#......#
......#..
..#......
'''.split()

assert get_score(f) == 200
print('\n'.join(f))
```
