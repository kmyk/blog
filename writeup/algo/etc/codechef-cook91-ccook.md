---
layout: post
alias: "/blog/2018/03/31/codechef-cook91-ccook/"
title: "CodeChef February Cook-Off 2018: Chef and Cook-Off"
date: "2018-03-31T02:12:44+09:00"
tags: [ "competitive", "writeup", "codechef" ]
"target_url": [ "https://www.codechef.com/COOK91/problems/CCOOK" ]
---

## note

-   某合宿 day1 no2 div1 A

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
for _ in range(n):
    a = list(map(int, input().split()))
    print([ "Beginner", "Junior Developer", "Middle Developer", "Senior Developer", "Hacker", "Jeff Dean" ][sum(a)])
```