---
layout: post
alias: "/blog/2018/04/05/codechef-cook79-dwnld/"
date: "2018-04-05T06:48:32+09:00"
tags: [ "competitive", "writeup", "codechef" ]
"target_url": [ "https://www.codechef.com/COOK79/problems/DWNLD" ]
---

# CodeChef Cook79: A. Download file

## note

-   やるだけ。やるだけなのに問題文が難読化されてなくてすごい。
-   某合宿 day3 no2 div1

## implementation

``` python
#!/usr/bin/env python3
tc = int(input())
for _ in range(tc):
    n, k = map(int, input().split())
    answer = 0
    for _ in range(n):
        t, d = map(int, input().split())
        free = min(k, t)
        k -= free
        t -= free
        answer += t * d
    print(answer)
```
