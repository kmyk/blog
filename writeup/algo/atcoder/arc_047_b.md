---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_047_b/
  - /writeup/algo/atcoder/arc-047-b/
  - /blog/2016/01/17/arc-047-b/
date: 2016-01-17T00:32:18+09:00
tags: [ "competitive", "writeup", "atcoder", "arc" ]
---

# AtCoder Regular Contest 047 B - 同一円周上

本番中に解けず。気合で実装すれば可能かもしれないがしたくない、という判断をして放棄。45度回せばよいことにすら気付いていなかったので駄目。

## [B - 同一円周上](https://beta.atcoder.jp/contests/arc047/tasks/arc047_b)

### 解法

45度回転変換$(x,y) \to (x+y,x-y)$を掛ければ、軸に並行な正方形で、与えられた点を全て周上に乗せるようなものの中心座標を答える問題になる。頑張って実装。
[解説](http://www.slideshare.net/chokudai/arc047)の図は分かりやすいので見ておくべき。

### 実装

``` python
#!/usr/bin/env python3
n = int(input())
ps = [tuple(map(int,input().split())) for i in range(n)]
qs = [(x+y, x-y) for (x,y) in ps] # rotate 45
xs = [x for (x,y) in qs]
ys = [y for (x,y) in qs]
dx = max(xs) - min(xs)
dy = max(ys) - min(ys)
l = max(dx, dy)
for q in \
        [ (min(xs) + l//2, min(ys) + l//2)
        , (min(xs) + l//2, max(ys) - l//2)
        , (max(xs) - l//2, min(ys) + l//2)
        , (max(xs) - l//2, max(ys) - l//2)
        ]:
    p = [((x+y)//2, (x-y)//2) for (x,y) in [q]][0]
    if len(set([abs(p[0] - x) + abs(p[1] - y) for (x,y) in ps])) == 1:
        break
print(*p)
```
