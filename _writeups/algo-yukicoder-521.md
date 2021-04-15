---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/521/
  - /blog/2017/06/02/yuki-521/
date: "2017-06-02T23:06:26+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/521" ]
---

# Yukicoder No.521 Cheeses and a Mousetrap(チーズとネズミ捕り)

$N = 1$がコーナーかなと思ったがそんなことはなかった。

## implementation

``` python
#!/usr/bin/env python3
n, k = map(int, input().split())
if k == 0 or n < k:
    ans = 0
else:
    if 2*k-1 == n:
        ans = n-1
    else:
        ans = n-2
print(ans)
```
