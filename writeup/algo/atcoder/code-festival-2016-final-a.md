---
layout: post
alias: "/blog/2016/11/28/code-festival-2016-final-a/"
date: "2016-11-28T02:15:06+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-final-open/tasks/codefestival_2016_final_a" ]
---

# CODE FESTIVAL 2016 Final: A - Where's Snuke?

rng\_58さんのトークライブでも利用されていた問題。

``` python
#!/usr/bin/env python3
import string
h, w = map(int, input().split())
for y in range(h):
    ps = input().split()
    for x, p in zip(string.ascii_uppercase, ps):
        if p == 'snuke':
            print(x + str(y+1))
```
