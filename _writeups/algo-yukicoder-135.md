---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/135/
  - /blog/2016/08/26/yuki-135/
date: "2016-08-26T00:36:17+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/135" ]
---

# Yukicoder No.135 とりあえず1次元の問題

sortして隣接要素間の差を見ればよい。pythonの`float('inf')`は単位元としてちょっと便利。

``` python
#!/usr/bin/env python3
n = int(input())
x = sorted(map(int,input().split()))
ans = float('inf')
for i in range(n-1):
    if x[i] != x[i+1]:
        ans = min(ans, x[i+1] - x[i])
if ans == float('inf'):
    ans = 0
print(ans)
```
