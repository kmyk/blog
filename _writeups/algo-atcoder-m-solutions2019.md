---
redirect_from:
  - /writeup/algo/atcoder/m-solutions2019/
layout: post
date: 2019-06-02T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# M-SOLUTIONS プロコンオープン

## C - Best-of-(2n-1)

引き分けの影響のしかたは一様なので $\frac{100}{a + b}$ を掛けることにすれば、 $c = 0$ として構わない。
青木君が勝つ場合も同様にして後で足せばよいので、高橋君が勝つ場合のみ考えて構わない。
さて、青木君の勝つ回数を $k$ とすれば ${} _ {n + k - 1} C _ k \cdot (\frac{a}{a + b})^n \cdot (\frac{b}{a + b})^k$ であるので、これをすべての $k \lt n$ について足し合わせれば答えである。
$O(N)$。

## D - Maximum Sum of Minimum

直線状の場合などから自明な上界 $\sum c_i - \max c_i$ が分かる。
これは適当にすれば達成できる。
$O(N)$。

## E - Product of Arithmetic Progression

あとで $d^n$ を掛けることにして $x/d, (x + d)/d, (x + 2d)/d, \dots$ を考えることで $d = 1$ にできる。
$d = 1$ であるとき $x \cdot (x + 1) \cdot \dots \cdot (x + n - 1) = (x + n - 1)! / (x - 1)!$ と階乗に落ちる。
計算量は $p = 1000003$ として $O(p \log p + Q)$ か。

## F - Random Tournament

まずは愚直 DP を考えると、区間 $[l, r)$ 中で $m$ が勝ち残る可能性があるかどうかを $\mathrm{dp}(l, r, m)$ とおき、漸化式
$$\mathrm{dp}(l, r, m) \iff \left(\exists i \in [l, m). i \triangleleft m \land \mathrm{dp}(l, m, i)\right) \land \left(\exists j \in [l + 1, r). j \triangleleft m \land \mathrm{dp}(m + 1, r, j)\right)$$
の $O(N^4)$ になる。ただし $a \triangleleft b$ は $a$ より $b$ が強いことを意味する。

ここに「最後に使ったもの」系の典型を導入する。
閉区間 $[l, r]$ 中で $l$ が勝ち残る可能性があるかどうかを $\mathrm{dp} _ L(l, r)$ とし、閉区間 $[l, r]$ 中で $r$ が勝ち残る可能性があるかどうかを $\mathrm{dp} _ R(l, r)$ とする。
このとき漸化式は
$$\mathrm{dp} _ L(l, r) \iff \exists m \in [l + 1, r]. m \triangleleft l \land \mathrm{dp} _ R(l + 1, m) \land \mathrm{dp} _ L(m, r)$$
のようになり、$O(N^3)$ に落ちる。
これは `bitset` で加速できる形であるので十分間に合って通る。

## 反省

-   C は「とりあえず簡単な場合に帰着させましょう」を $2$ 回やる。すぐ解けた
-   D は「自明な上界を考えてみましょう」すると解けるけど、かなり時間がかかった。これが一番無理だと思う
-   E は「自明な場合を考えてみましょう」して「問題を整理しよう」で解けるけど、私には無理だった。ちゃんと「まずは自明な場合を考える！ (素振り) まずは自明な場合を考える！ (素振り) まずは自明な場合を考える！ (素振り)」ってしないとだめそう
-   F は「とりあえず愚直 DP を考えましょう」からの「典型パターンで加速する」なので解けた。どうして開かなかったのか。問題はすべて読みましょう

## リンク

-   <https://atcoder.jp/contests/m-solutions2019>
-   <https://atcoder.jp/contests/m-solutions2019/submissions/5737909>
-   <https://atcoder.jp/contests/m-solutions2019/submissions/5737913>
-   <https://atcoder.jp/contests/m-solutions2019/submissions/5738147>
-   <https://atcoder.jp/contests/m-solutions2019/submissions/5739350>
