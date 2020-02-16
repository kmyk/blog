---
layout: post
date: 2018-08-25T17:16:58+09:00
tags: [ "competitive", "writeup", "atcoder", "math" ]
"target_url": [ "https://beta.atcoder.jp/contests/summerfes2018-div1/tasks/summerfes2018_e" ]
---

# Summer Festival Contest 2018 (Division 1): E - 石積み (Pyramid Piling)

## 解法

数学。$$O(1)$$。

まず一辺$$s$$の$N$次元空間上の三角形状に詰むのに必要な小石の数$$f(N, s)$$から考えよう。
定義より $$f(N, s) = \# \left\{ (x_1, x_2, \dots, x_N) \in \mathbb{N}^N \mid \sum x_i \lt s \right\}$$ だが
等号の形で書き直せば $$f(N, s) = \# \left\{ (x_1, x_2, \dots, x_N, x _ {N + 1}) \in \mathbb{N}^{N + 1} \mid \sum _ {1 \le i \le N + 1} x_i = s - 1 \right\} = {} _ {s - 1 + N} C_N$$ とできる。
よって答えは $${} _ {s_1 - 1 + N} C _ N = {} _ {s_2 - 1 + N - 1} C _ {N - 1}$$ かつ $$s_1 \ne s_2$$ な整数 $$s_1, s_2$$ を求めればよい。
$$s_1 \lt s_2$$となることを使いつつ、ここからさらに整理していこう。

-   $${} _ {s_1 - 1 + N} C _ N = {} _ {s_2 - 1 + N - 1} C _ {N - 1}$$
-   $$(s_1 - 1 + N)! \cdot (s_2 - 1)! \cdot (N - 1)! = (s_1 - 1)! \cdot (s_2 - 1 + N - 1)! \cdot N!$$
-   $$(s_1 - 1 + N)! \cdot (s_2 - 1)! = (s_1 - 1)! \cdot (s_2 - 1 + N - 1)! \cdot N$$
-   $${} _ {s_2 - 1} P _ {s_2 - s_1} = {} _ {s_2 - 1 + N - 1} P _ {s_2 - s_1 - 1} \cdot N$$
-   $${} _ {s_2 - 1} P _ {s_2 - s_1} \cdot (s_1 + N - 1) = {} _ {s_2 - 1 + N - 1} P _ {s_2 - s_1} \cdot N$$

さらにここで簡単になることを祈りながら $$s_2 - s_1 = 1$$ としてみると

-   $$(s_2 - 1) \cdot (s_2 - 1 + N - 1) = (s_1 + N - 1) \cdot N$$
-   $$s_1 \cdot (s_1 + N - 1) = (s_1 + N - 1) \cdot N$$

を満たせばよい。
ここで $$s_1 = N$$ と置くと式が成り立つため、 $$(s_1, s_2) = (N, N + 1)$$ は答えのひとつ。

## メモ

sagemath上とかで実験しながらやるとよい。本番中には整理し切れなかったが。

## 実装

``` awk
#!/usr/bin/awk -f
$0=$1" "$1+1
```
