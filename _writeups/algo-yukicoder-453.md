---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/453/
  - /blog/2016/12/05/yuki-453/
date: "2016-12-05T04:26:59+09:00"
tags: [ "competitive", "writeup", "yukicoder", "linear-programming-problem" ]
"target_url": [ "http://yukicoder.me/problems/no/453" ]
---

# Yukicoder No.453 製薬会社

## solution

線形計画問題。$O(1)$。

問題を整理すると:
$$ \begin{array}{cc}
\text{max:} & 1000a + 2000b \\\\
\text{sub to:} & \frac{3}{4}a + \frac{2}{7}b \le C \\\\
               & \frac{1}{4}a + \frac{5}{7}b \le D \\\\
               & a, b \ge 0
\end{array} $$

最適解になりうるのは多面体の頂点のみである。
つまり、以下の$4$本の直線の交点を全て試せば答えが見つかる。
$$ \begin{array}{c}
\frac{3}{4}a + \frac{2}{7}b = C \\\\
\frac{1}{4}a + \frac{5}{7}b = D \\\\
a = 0 \\\\
b = 0
\end{array} $$

## implementation

``` python
#!/usr/bin/env python3
c, d = map(int, input().split())
a0 = min(c * 4/3, d * 4/1)
b0 = min(c * 7/2, d * 7/5)
a = 4/13 * (5*c - 2*d)
b = 7/13 * (3*d - c)
if a < 0 or b < 0:
    a, b = 0, 0
print(max([ 1000*a0, 2000*b0, 1000*a + 2000*b ]))
```
