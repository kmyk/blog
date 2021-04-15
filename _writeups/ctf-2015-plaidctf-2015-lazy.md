---
layout: post
redirect_from:
  - /writeup/ctf/2015/plaidctf-2015-lazy/
  - /blog/2017/09/20/plaidctf-2015-lazy/
date: "2017-09-20T18:31:17+09:00"
tags: [ "ctf", "writeup", "plaidctf", "crypto", "knapsack-cipher", "lll-algorithm", "clos-method", "low-density-attack" ]
"target_url": [ "https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/crypto/lazy" ]
---

# PlaidCTF CTF 2015: Lazy

## problem

Merkle-Hellman knapsack暗号
公開鍵と暗号文が与えられるので解け。

## Merkle-Hellman knapsack暗号

公開鍵暗号。
超増加列$\mathbf{a}$、法$N \gt \sum a\_i$、$N$と互いに素な$r$の$3$つ組$(\mathbf{a}, N, r)$が秘密鍵。
公開鍵は$b\_i = ra\_i \bmod N$で得られる数列$\mathbf{b}$。

超増加列とは$\sum\_{j \lt i} a\_i \lt a\_i$を満たす列。
ある数が$\sum a\_i$より小さいなら、その部分和として表現できるかの判定が大きい方から見ていく単純な方法により$O(n)$ででき、さらにその構成方法が一意であるという性質を持つ。
具体例としては$( 1, 2, 4, 8, \dots, 2^n )$。

列$\mathbf{a}$の長さを$n = \mathrm{lh}(\mathbf{a})$と置き、平文$m \lt 2^n$に対し$m\_i \in \\{ 0, 1 \\}$を$m$の$i$-bit目として、暗号文$c = \sum\_{i \lt n} b\_im\_i$。
$m$は単に$0, 1$の列と見た方がよく、$i$-bit目というのが下から数えてなのか上から数えてなのかはあまり問題にならない。
復号は$r^{-1}c \bmod N = \sum\_{i \lt n} a\_im\_i$を考え、$\mathbf{a}$が超増加列であることより$m$を求める。

## solution

CLOS法。
低密度攻撃のひとつで、密度$d = \frac{n}{\log\_2 \max b\_i} \lt 0.9408\dots$のとき復号できる。
今回は$d \approx 0.900711 \lt 0.9408\dots$なので利用可能。

CLOS法について考える前に、まず単純な方法としてLO法(Lagarias-Odlyzko Algorithm)を見る。$(n + 1) \times (n + 1)$行列 $$ \mathbb{B} = \left( \begin{matrix}
    \mathbf{b} & I \\\\
    -c  & \mathbf{0} \\\\
\end{matrix} \right) = \left( \begin{matrix}
    b_0 & 1 & 0 & 0 & \dots & 0 \\\\
    b_1 & 0 & 1 & 0 & \dots & 0 \\\\
    b_2 & 0 & 0 & 1 & \dots & 0 \\\\
    \vdots & \vdots & \vdots & \vdots & \ddots & \vdots \\\\
    b_{n-1} & 0 & 0 & 0 & \dots & 1 \\\\
    -c & 0 & 0 & 0 & \dots & 0 \\\\
\end{matrix} \right)
$$ を考え、これを(行vectorをその$1$本とする)基底と見てLLL algorithmを使う。
縮退された基底の中から、左端が$0$でそれ以外は$0, 1$なvectorという形で$m$が得られる。
そのようなものがなければ$m\_i = 0$のときと$m\_i = 1$のときで非対称性が生じているため、$0, 1$を入れ換えるような修正をしてもう一度これを行う。
[このwriteup](http://gnoobz.com/plaid-ctf-2015-lazy-writeup.html)ではこの方法を使っている。

CLOS法に戻る。
先の方法では$m$を基底の中のvectorとしてそのまま求めていたために非対称性が生じていた。
これを解消する方向に拡張していったのがCLOS法、と考えてよさそう。
$m \in \\{ 0, 1 \\}^n$を直接求めるのでなく、$0 \mapsto -1$と置き換えて$\tilde{m} \in \\{ -1, +1 \\}^n$を求める。

具体的には基底を
$$ \mathbb{B}' = \left( \begin{matrix}
    \mathbf{b} & 2I \\\\
    -c  & \mathbf{-1} \\\\
\end{matrix} \right) = \left( \begin{matrix}
    b_0 & 2 & 0 & 0 & \dots & 0 \\\\
    b_1 & 0 & 2 & 0 & \dots & 0 \\\\
    b_2 & 0 & 0 & 2 & \dots & 0 \\\\
    \vdots & \vdots & \vdots & \vdots & \ddots & \vdots \\\\
    b_{n-1} & 0 & 0 & 0 & \dots & 2 \\\\
    -c & -1 & -1 & -1 & \dots & -1 \\\\
\end{matrix} \right) $$
とする。
なお基底を張るときの気持ちから$-c, \mathbf{-1}$としているが、別に$c, \mathbf{1}$でもかまわない。
さらにLLLに左端を優先的に$0$にするよう伝えるため、適当な大きな定数$K$を使って
$$ \mathbb{B}'' = \left( \begin{matrix}
    K\mathbf{b} & 2I \\\\
    -Kc  & \mathbf{-1} \\\\
\end{matrix} \right) $$ とすれば完成。
これをLLLに食わせれば基底の中に左端が$0$でそれ以外は$-1, +1$なvectorという形で$\tilde{m}$が得られ、$m$が得られる。
注意として、元々の基底では$\frac{1}{2}$と有理数がでてくるが、今回のものは全体を$2$倍しすべて整数になるように修正してある。

## references

-   [katagaitai workshop #7 crypto ナップサック暗号と低密度攻撃](https://www.slideshare.net/trmr105/katagaitai-workshop-7-crypto)
-   [Merkle-Hellmanナップサック暗号 - Wikipedia](https://ja.wikipedia.org/wiki/Merkle-Hellman%E3%83%8A%E3%83%83%E3%83%97%E3%82%B5%E3%83%83%E3%82%AF%E6%9A%97%E5%8F%B7)
-   J. C. Lagarias and A. M. Odlyzko. 1985. Solving low-density subset sum problems. J. ACM 32, 1 (January 1985), 229-246. DOI=http://dx.doi.org/10.1145/2455.2461
    -   LO法
-   M. J. Coster, B. A. LaMacchia, A. M. Odlyzko, and C. P. Schnorr. 1991. An improved low-density subset sum algorithm. In Proceedings of the 10th annual international conference on Theory and application of cryptographic techniques (EUROCRYPT'91), Donald W. Davies (Ed.). Springer-Verlag, Berlin, Heidelberg, 54-67.
    -   CLOS法

## implementation

``` python
#!/usr/bin/env sagemath

# load values
import ast
with open('pubkey.txt') as fh:
    b = ast.literal_eval(fh.read())
with open('ciphertext.txt') as fh:
    c = int(fh.read())
n = len(b)
print '[*] pubkey: b =', b
print '[*] ciphertext: c =', c

# check the density
d = float(n / log(max(b), 2))
print '[*] density: d =', d


# low-density attack, CLOS method
# prepare a basis
MULTIPLIER = 100
B = matrix(ZZ, n + 1, n + 1)
B.set_block(0, 0, MULTIPLIER * matrix(n, 1, b))
B.set_block(n, 0, MULTIPLIER * matrix([ - c ]))
B.set_block(0, 1, 2 * identity_matrix(n))
B.set_block(n, 1, matrix([ -1 ] * n))
print '[*] basis: B =', B

# LLL algorithm
for x in B.LLL():
    if x[0] == 0 and all(x_i in [-1, +1] for x_i in x[1 :]):
        print '[*] found: x =', x

        # decode x
        m = 0
        for x_i in reversed(x[1 :]):
            m *= 2
            m += int(x_i == +1)
        print '[*] plaintext: m =', m
        print '[*]', repr(hex(m).decode('hex'))
```

---

# PlaidCTF CTF 2015: Lazy

-   2017年  9月 26日 火曜日 13:39:21 JST
    -   LO法とCLOS法の論文が逆になってたので修正
