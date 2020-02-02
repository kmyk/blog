---
layout: post
alias: "/blog/2016/09/25/code-festival-2016-quala-b/"
date: "2016-09-25T03:26:24+09:00"
title: "CODE FESTIVAL 2016 qual A: B - 仲良しうさぎ / Friendly Rabbits"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2016-quala/tasks/codefestival_2016_qualA_b" ]
---

$a\_{a_i} = i$なやつの数を数えてその半分。

``` python
#!/usr/bin/env python3
n = int(input())
a = list(map(lambda s: int(s)-1, input().split()))
ans = 0
for i in range(n):
    if a[a[i]] == i and i < a[i]:
        ans += 1
print(ans)
```
