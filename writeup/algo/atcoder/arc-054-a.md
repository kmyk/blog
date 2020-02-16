---
layout: post
alias: "/blog/2016/05/25/arc-054-a/"
date: 2016-05-25T19:24:25+09:00
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc054/tasks/arc054_a" ]
---

# AtCoder Regular Contest 054 A - 動く歩道

pythonの`%`は必ず非負正数を返してくれてよい。

``` python
#!/usr/bin/env python3
l, x, y, s, d = map(int,input().split())
ans = ((d - s) % l) / (x + y)
if y > x:
    ans = min(ans, ((s - d) % l) / (y - x))
print('%.10f' % ans)
```
