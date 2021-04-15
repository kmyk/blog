---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/313/
  - /blog/2016/06/10/yuki-313/
date: 2016-06-10T02:06:24+09:00
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/686" ]
---

# Yukicoder No.313 π

golf場で出した方がうけそう

## implementation

``` python
#!/usr/bin/env python3
pi = [20104, 20063, 19892, 20011, 19874, 20199, 19898, 20163, 19956, 19841]
s = input()
cnt = [s.count(str(i)) for i in range(10)]
for i in range(10):
    if cnt[i] < pi[i]:
        y = i
    if cnt[i] > pi[i]:
        x = i
print(x, y)
```

ところで、

``` sh
$ cat a.sh
#!/bin/sh
tr -d . | sed -s 's/\B/\n/g' | diff - <(tail -n +5 "$0" | gunzip | tr -d . | sed -s 's/\B/\n/g') | grep '^[<>]' | tr -cd 0-9 | sed -e 's/\B/ /'
echo
exit 0
$ cat pi.txt | gzip > pi.gz
$ cat a.sh | pi.gz > b.sh
```

みたいにしたら80KBでした。
