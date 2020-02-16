---
layout: post
redirect_from:
  - /blog/2016/05/28/abc-038-c/
date: 2016-05-28T23:00:03+09:00
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc038/tasks/abc038_c" ]
---

# AtCoder Beginner Contest 038 C - 単調増加

連続する区間長を持ってなめて$O(N)$

``` python
#!/usr/bin/env python3
n = int(input())
a = list(map(int,input().split()))
ans = 1
l = 1
for i in range(1,n):
    if a[i-1] < a[i]:
        l += 1
    else:
        l = 1
    ans += l
print(ans)
```
