---
layout: post
date: 2019-04-16T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# AtCoder Grand Contest 031: D - A Sequence of Permutations

## 問題

置換 $p, q \in \mathfrak{S} _ N$ が与えられる。
次のように定義する:

-   $a_1 = p$
-   $a_2 = q$
-   $a _ {n+2} = a _ {n+1} \circ a_n^{-1}$

このとき $a_K$ を答えよ。

## 考察過程

1.  愚直 $O(NK)$
1.  とりあえず対称群の言葉で書き直した (整理)
1.  見ていけば周期性がありそう (推測)
1.  周期性なかった (実験)
1.  連結成分ごとに解く？
1.  やたら疎な行列の累乗に持ち込みたい
1.  上から落としていってうまく再帰できないか

    $$ \begin{array}{ccl}
        a _ {10} & = & a_9 \circ a_8^{-1} \\
                 & = & a_8 \circ a_7^{-1} \circ a_8^{-1} \\
                 & = & a_7 \circ a_6^{-1} \circ a_7^{-1} \circ a_6 \circ a_7^{-1} \\
                 & = & a_6 \circ a_5^{-1} \circ a_6^{-1} \circ a_5 \circ a_6^{-1} \circ a_6 \circ a_5 \circ a_6^{-1} \\
    \end{array} $$
    
    これ下からやるのと同じ
    
    ``` python
    #!/usr/bin/env python3
    import re
    
    a = []
    a += [ 'p' ]
    a += [ 'q' ]
    for _ in range(14):
        a += [ a[-1] + ''.join(reversed(a[-2])).swapcase() ]
    print(*a, sep='\n')
    
    b = [ re.subn(r'(pP|Pp|qQ|Qq)', '', a_i)[0] for a_i in a ]
    print(*b, sep='\n')
    ```
    
    ``` console
    $ ./a.py
    p
    q
    qP
    qPQ
    qPQpQ
    qPQpQqpQ
    qPQpQqpQqPqpQ
    qPQpQqpQqPqpQqPQqPqpQ
    qPQpQqpQqPqpQqPQqPqpQqPQpQqPQqPqpQ
    qPQpQqpQqPqpQqPQqPqpQqPQpQqPQqPqpQqPQpQqpQqPQpQqPQqPqpQ
    qPQpQqpQqPqpQqPQqPqpQqPQpQqPQqPqpQqPQpQqpQqPQpQqPQqPqpQqPQpQqpQqPqpQqPQpQqpQqPQpQqPQqPqpQ
    qPQpQqpQqPqpQqPQqPqpQqPQpQqPQqPqpQqPQpQqpQqPQpQqPQqPqpQqPQpQqpQqPqpQqPQpQqpQqPQpQqPQqPqpQqPQpQqpQqPqpQqPQqPqpQqPQpQqpQqPqpQqPQpQqpQqPQpQqPQqPqpQ
    ...
    ```
    
1.  それでも周期性に頼る他はなさそう。「ある $k$ で不動点 $a_k(i) = i$ がある」を仮定するとどうか

    $$ \begin{array}{ccl}
        a _ {k+1}(i) & = & (a_k \circ a _ {k-1}^{-1})(i) \\
                     & = & a _ {k-1}^{-1}(i) \\
        a _ {k+2}(i) & = & (a _ {k+1} \circ a_k^{-1})(i) \\
                     & = & a _ {k+1}(i) \\
                     & = & a _ {k-1}^{-1}(i) \\
        a _ {k+3}(i) & = & (a _ {k+2} \circ a _ {k+1}^{-1})(i) \\
                     & = & (a _ {k-1}^{-1} \circ a _ {k-1})(i) \\
                     & = & i \\
    \end{array} $$
    
    この方向だと $O(N^2)$ がありそう
    
1.  「ある $k$ で等式 $ a_ {k+1}(i) = a_k(i)$ がなりたつ」を仮定するとどうか

    $$ \begin{array}{ccl}
        a _ {k+2}(i) & = & (a _ {k+1} \circ a_k^{-1})(i) \\
        (a _ {k+2} \circ a_k)(i) & = & a _ {k+1}(i) \\
        a _ {k+2} (a_k(i)) & = & a_k(i) \\
    \end{array} $$
    
    よって $a _ {k+2}$ が不動点 $a_k(i)$ を持つ
    
1.  「ある $k$ で等式 $ a_ {k+2}(i) = a_k(i)$ がなりたつ」を仮定するとどうか

    $$ \begin{array}{ccl}
        a _ {k+2}(i) & = & a_k(i) \\
        & = & (a _ {k+1} \circ a_k^{-1})(i) \\
        a_k^2(i) & = & a _ {k+1}(i) \\
    \end{array} $$
    
    苦しい
    
1.  諦め。周期性の検討以外に手を思い付かなかったため

## 解法

$a_n = A_n \circ B_n \circ A_n^{-1}$ と整理すると $(A_n, B_n)$ の列に関して周期性がある。

## 反省

-   $a_n = ABA^{-1}$ という発想がなかった
-   周期性までは見えていた。 $a_n^{-1}$ も併記して観察すれば辿り着けていたかもしれない

## 特性方程式

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">(Dがmod6で場合分けになるの、普通に整数の場合で漸化式a[i]=a[i-1]-a[i-2]考えたら特性方程式の解が1の6乗根(実際周期6になる)だし不思議ではないな)</p>&mdash; チョコラスク (@nuo_chocorusk) <a href="https://twitter.com/nuo_chocorusk/status/1106984852971089920?ref_src=twsrc%5Etfw">2019年3月16日</a></blockquote>

乗法群でなく加法群として見て $a _ {i+2} = a _ {i+1} - a_i$ の特性方程式 $x^2 = x - 1$ の解は $x = \frac{1 \pm \sqrt{-3}}{2}$ となる。これは符号がどちらの場合でも $x^3 = -1$ つまり $x^6 = 1$ となるような点である。

## リンク

-   <https://atcoder.jp/contests/agc031/tasks/agc031_d>
-   <https://atcoder.jp/contests/agc031/submissions/4993240>
-   <https://not-522.appspot.com/contest/6367023646900224>
