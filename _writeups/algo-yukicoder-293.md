---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/293/
  - /blog/2016/06/07/yuki-293/
date: 2016-06-07T18:18:44+09:00
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/728" ]
---

# Yukicoder No.293 4>7の世界

問題文が明快でない。

## solution

$O(\min \\{ \log A, \log B \\})$。

問題で指定されたそれそのものが答えである。
ただコードに翻訳すればよい。

## implementation

``` python
#!/usr/bin/env python3
def lt(x, y):
    if x == '7' and y == '4':
        return True
    elif x == '4' and y == '7':
        return False
    else:
        return x < y
xs, ys = input().split()
if len(xs) < len(ys):
    ans = ys
elif len(xs) > len(ys):
    ans = xs
else:
    for x, y in zip(xs, ys):
        if lt(x, y):
            ans = ys
            break
        elif lt(y, x):
            ans = xs
            break
    else:
        assert xs == ys
        ans = xs
print(ans)
```

---

# Yukicoder No.293 4>7の世界

-   2017年  1月 30日 月曜日 19:37:09 JST
    -   線形だよという意味のつもりで$O(N)$と書いていたが、混乱を招き指摘されたので修正した
