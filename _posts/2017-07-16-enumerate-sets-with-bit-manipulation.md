---
category: blog
layout: post
date: "2017-07-16T00:26:26+09:00"
tags: [ "optimization", "bits" ]
---

# bit演算による集合の列挙

## 順序数

簡単のための略記として[Von Neumannによる順序数](https://en.wikipedia.org/wiki/Ordinal_number#Von_Neumann_definition_of_ordinals)を有限の範囲で導入しておく。
つまり自然数$n \ge 0$は集合$\\{ 0, 1, 2, \dots, n - 1 \\}$と同一視するものとする。

## 順序数$n$の部分集合$x \subseteq n$

$2^n$個存在。

昇順に列挙:

``` c
for (int x = 0; x < (1 << n); ++ x) {
    ...
}
```

逆順にしたい場合も簡単。

## 集合$z$の部分集合$y \subseteq z$

$2^{\|z\|}$個。

昇順なら:

``` c
for (int y = 0; ; y = (y - z) & z) {
    ...
    if (y == z) break;
}
```

降順なら:

``` c
for (int y = z; ; y = (y - 1) & z) {
    ...
    if (y == 0) break;
}
```

更新部分は`-- y &= x`としてもよい。

ちなみに集合$z$に対し$x \subseteq y \subseteq z$な組$(x, y)$はちょうど$3^{\|z\|}$個ある。各要素$a \in z$について$a \in z$と$a \not\in z \land a \in y$と$a \not\in y$の$3$通りずつあるためで、$4^{\|z\|}$個ではない。

## 集合$x$を包含する集合$y \supseteq x$ (ただし$y \subseteq n$)

$2^{n - \|y\|}$個。

昇順:

``` c
for (int y = x; y < (1 << n); y = (y + 1) | x) {
    ...
}
```

更新部分は`++ y |= x`としてもよい。

降順に列挙するには次の$x \subseteq y \subseteq z$において$z = n$とすればよい。

## 集合$x, z$に対し集合$y$で$x \subseteq y \subseteq z$

$2^{\|z\| - \|x\|}$個。

$z \setminus x$の部分集合$y^{-}$を列挙して$y = y^{-} \cup x$とすればよい。

## 要素数$\|x\| = k$な集合$x$ (ただし$x \subseteq n$)

${}\_nC\_k$個。

昇順:

``` c
for (int x = (1 << k) - 1; x < (1 << n); ) {
    ...
    int t = x | (x - 1);
    x = (t + 1) | (((~ t & - ~ t) - 1) >> (__builtin_ctz(x) + 1));
}
```

更新部分は次のようにもできるが、除算を含むため遅い。

```
    int y = x & - x;
    int z = x + y;
    x = (((x & ~ z) / y) >> 1) | z;
```

## 集合$y$の要素のsingleton $\\{ x \\} \; \text{for} \; x \in y$

${}\_{\|y\|}C\_1 = \|y\|$個。

昇順:

``` c
for (int x = y & - y; x; x = y & (~ y + (x << 1))) {
    ...
}
```

更新は`y = x & ~ (x - (y << 1))`でもよい。
立っているbitだけを考えたときに連続する$k$bitなども同じ更新方法で列挙できるが、あまり使わないだろう。

$x$から最下位bitを取り出して破壊的に消していくのでもよい。

## 要素数$\|x\| = k$な部分集合$x \subseteq y$

${}\_{\|y\|}C\_k$個。

難しいようだ。
$k$が定数の場合に限るが、singletonの取り出しで$k$重loopを作ることで実現可能。
$x \supseteq z$という制約を加えたいときは、要素数を固定しない場合にしたのと同様の修正をする。

## 参考文献

-   <http://graphics.stanford.edu/~seander/bithacks.html>
-   <http://homolog.us/blogs/blog/2014/12/04/the-entire-world-of-bit-twiddling-hacks/>
-   <http://www.catonmat.net/blog/low-level-bit-hacks-you-absolutely-must-know/>
