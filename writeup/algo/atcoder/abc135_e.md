---
redirect_from:
layout: post
date: 2019-10-18T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# AtCoder Beginner Contest 135: E - Golf

## 考察

-   菱形のやつ。自明では？ そうでもないか
-   たいていの点 $p = (x, y)$ で回数 $\lceil d(0, p) / K \rceil$ じゃないのかな
-   ところで Manhattan 距離とくれば $45$ 度回転
-   不可能な例はどんなの？ サンプルの $K = 4600$ はわざとらしすぎるだろ
-   $K$ が偶数のとき偶数位置のマスには移動不能。$K$ が奇数なら $(0, 0); (1, K - 1); (1 + \frac{K - 1}{2}, \frac{K - 1}{2}); (1, 0)$ と移動できるのですべての点に移動可能
-   $K$ は奇数と仮定してよい。$2K$ で点 $2p = (2x, 2y)$ に移動するのは $K$ で点 $p = (x, y)$ に移動するのに同じ
-   次は嘘: $K$ が奇数のとき $d(0, p) \le K$ の点には高々 $2$ 手で移動できる
-   $f(1) = (0, 1, 2, 3, 4, 5, 6, 7, \dots)$
-   $f(3) = (0, 3, 2, 1, 2, 3, 2, 3, \dots)$
-   実験した方が速い気がしてきた。まあ精進なので、手でなくちゃんと頭を動かしましょう
-   $f(5) = (0, 3, 2, 3, 2, 1, 2, 3, 2, 3, 2, \dots)$
-   $d(0, p) = K$ な点まで見ると $(0, 3, 2, 3, 2, \dots, 3, 2, 1)$ ぽい
-   $d(0, p) \lt 2K$ な点では特別に、それより先の $\lt 2K$ で調整して愚直でよい
-   解けたね。実装します
-   $K$ は奇数の仮定は嘘では？ $K = 4$ のときは半分に圧縮してもなお奇数なので

## 解法

まず到達可能性について。
$K \equiv 0 \pmod{2}$ かつ $\vert x \vert + \vert y \vert \equiv 1 \pmod{2}$ なら不可能。それ以外なら可能。

与えられた点 $p = (x, y)$ に対し、そのスコアの最小値 $f_K(x, y)$ をひとつ減らす ($f_K(x - dx, y - dy) = f_K(x, y) - 1$ となる) ような $(dx, dy)$ を $O(1)$ 程度で求められればよい。
$\vert x \vert + \vert y \vert \in \lbrace 0, K \rbrace$ の場合は明らかである。それ以外の場合について次のように場合分け:

-   $\vert x \vert + \vert y \vert \lt 2K$ かつ $\vert x \vert + \vert y \vert \equiv 0 \pmod{2}$ のとき: このとき必ず $f_K(x, y) = 2$ である。まじめに計算する必要がある。$z = \frac{2K - \vert x \vert + \vert y \vert}{2}$ が $z \in \lbrace dx, dy, -dx, -dy \rbrace$ を満たす
-   $\vert x \vert + \vert y \vert \lt 2K$ かつ $\vert x \vert + \vert y \vert \equiv 1 \pmod{2}$ のとき: このとき必ず $f_K(x, y) = 3$ である。ランダムに $(dx, dy)$ を生成すると、十分な確率で $f_K(x - dx, y - dy) = 2$ なものが見つかる
-   $\vert x \vert + \vert y \vert \ge 2K$ のとき: このとき必ず $f_K(x, y) \ge 2$ である。貪欲に近づけばよい

## メモ

-   考察 $0.5$ 時間 + 実装 $1.5$ 時間 ぐらい。TLE + WA で $2$ ペナ。ひどい
-   ちゃんとすべて詰めてから実装を始めましょう
-   $K$ の制約がもう少し小さければ $\vert x \vert + \vert y \vert \lt 2K$ かつ $\vert x \vert + \vert y \vert \equiv 0 \pmod{2}$ の部分を近傍の全列挙で回避できていた。私は $K$ の制約を勘違いして TLE しました

## リンク

-   <https://atcoder.jp/contests/abc135/tasks/abc135_e>
-   提出: <https://atcoder.jp/contests/abc135/submissions/8004974>
