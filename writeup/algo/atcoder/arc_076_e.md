---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_076_e/
  - /writeup/algo/atcoder/arc-076-e/
  - /blog/2017/12/31/arc-076-e/
date: "2017-12-31T21:19:17+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc076/tasks/arc076_c" ]
---

# AtCoder Regular Contest 076: E - Connected?

$R$と$C$は逆にしたいなあと思う

## solution

どちらか一方以上が周上に乗っていない対は無視してよい。
平面上でなく環上に乗っている、特に両端が繋がった数列と見てよい。
`NO`になるのは入力例$4$のように交差があるとき。
環状の数列上で同じ数字が隣り合っていれば消すことを繰り返し、全て消せるか判定すればよい。$O(N)$。

## implementation

``` python
#!/usr/bin/env python3
w, h, n = map(int, input().split())
def proj(x, y):
    if y == 0:
        return x
    elif x == w:
        return w + y
    elif y == h:
        return w + h + (w - x)
    elif x == 0:
        return w + h + w + (h - y)
    else:
        return None
ps = []
for i in range(n):
    x1, y1, x2, y2 = map(int, input().split())
    p1 = proj(x1, y1)
    p2 = proj(x2, y2)
    if p1 is not None and p2 is not None:
        ps += [ (p1, i), (p2, i) ]
ps.sort()
stk = []
for _, i in ps:
    if stk and stk[-1] == i:
        stk.pop()
    else:
        stk.append(i)
result = not stk
print([ 'NO', 'YES' ][ result ])
```
