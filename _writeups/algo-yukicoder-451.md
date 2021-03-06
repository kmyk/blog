---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/451/
  - /blog/2016/12/05/yuki-451/
date: "2016-12-05T04:26:55+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/451" ]
---

# Yukicoder No.451 575

まだアドベコン全体としては終わってないが、個々の問題の解説は公開されてるようだ。

## solution

条件式を展開すると:

$$ \begin{array}{l}
b\_{2i  } = a\_{2i  } - a\_{2i+1} \\\\
b\_{2i+1} = a\_{2i+1} + a\_{2i+2}
\end{array} $$

整理して:

$$ \begin{array}{l}
a_1 = a_1 \\\\
a\_{2i+2} = - a\_{2i+1} + b\_{2i+1} \\\\
a\_{2i+1} = a\_{2i} - b\_{2i}
\end{array} $$

これに加えて制約
$$
\forall i. 1 \le a_i \le 10^{18}
$$
があるので、$a_1$を適当に決めて各$a_i$がこの範囲に収まるようにしたい。

$a_1$を動かした時の他の項の変化を見ると:

$$ \begin{array}{l}
a_1 = a_1 \\\\
a_2 = - a_1 + b_1 \\\\
a_3 = - a_1 + b_1 - b_2 \\\\
a_4 = a_1 - b_1 + b_2 + b_3 \\\\
a_5 = a_1 - b_1 + b_2 + b_3 - b_4 \\\\
a_6 = - a_1 + b_1 - b_2 - b_3 + b_4 + b_5
\vdots
\end{array} $$

であるので、$\lfloor \frac{i}{2} \rfloor$の偶奇によって各項に対し$\pm 1$倍の線形で効いてくる。
適当な$a_1 = 0$としていったん計算して各項で$1 \le a_i + k a_0 \le 10^{18}$とすれば$a_0$の動く範囲が得られる。
この範囲が空であるかどうかを見て空でなければ適当に取り出して計算すればよい。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
b = [ int(input()) for _ in range(n) ]
def f(a1):
    a = [ None ] * (n+1)
    a[0] = a1
    for i in range(n):
        if (i+1 + 1) % 2 == 0:
            a[i+1] = - a[i] + b[i]
        else:
            a[i+1] = a[i] - b[i]
    return a
lower = 1
upper = 10**18
a = f(0)
for i in range(n+1):
    if ((i+1) // 2) % 2 == 0:
        lower = max(lower, 1      - a[i])
        upper = min(upper, 10**18 - a[i])
    else:
        lower = max(lower, a[i] - 10**18)
        upper = min(upper, a[i] - 1     )
if lower <= upper:
    print(n+1)
    for ai in f(lower):
        print(ai)
else:
    print(-1)
```
