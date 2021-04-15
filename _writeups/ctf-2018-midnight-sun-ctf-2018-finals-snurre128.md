---
redirect_from:
  - /writeup/ctf/2018/midnight-sun-ctf-2018-finals-snurre128/
layout: post
date: "2018-06-28T22:36+09:00"
tags: [ "ctf", "writeup", "midnight-sun-ctf", "crypto", "lfsr", "linearity" ]
"target_url": [ "https://ctftime.org/event/635" ]
---

# Midnight Sun CTF Finals 2018: Snurre128

## note

本番で我々のチームが唯一解けなかった問題。

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">今回のCTFではweb pwn revは全完してもらったにもかかわらずcryptoの最後の1問を落として優勝を逃したため、個人的に反省をしています</p>&mdash; うさぎ (@a3VtYQo) <a href="https://twitter.com/a3VtYQo/status/1008385717473566720?ref_src=twsrc%5Etfw">2018年6月17日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

以下はeshihoがまとめた結果を読んで理解/実装した結果で、そもそもの出展はnomeaningさんやhellmanの[writeup](http://mslc.ctf.su/wp/midnight-ctf-2018-finals-snurre128/)です。
Learning Parity with Noise問題という名前も出ていましたが単に線形代数として読みました。

## problem

128bitの[linear feedback shift register](https://ja.wikipedia.org/wiki/%E7%B7%9A%E5%BD%A2%E5%B8%B0%E9%82%84%E3%82%B7%E3%83%95%E3%83%88%E3%83%AC%E3%82%B8%E3%82%B9%E3%82%BF)がある。
その出力の系列が1600bit与えられるので初期状態を復元せよ。
ただし出力関数は非線形な<span>$f(x) = x_0 + x_1 + x_2 + x_{31} + x_1 x_2 x_3 x_{64} x_{123} + x_{25} x_{31} x_{32} x_{126}$</span>である。

## solution

### 概要

出力関数が線形ならば、単に行列を解くだけで初期状態が求まる。
今回は非線形だが線形関数で近似し<span>$l(x) = x_0 + x_1 + x_2 + x_{31}$</span>と考えることで無理矢理これを行う。
積を含む項が<span>$x_1 x_2 x_3 x_{64} x_{123}, \; x_{25} x_{31} x_{32} x_{126}$</span>と大きく、よってそれぞれ$1$になる確率は$\frac{1}{16}, \frac{1}{32}$と小さいため、これが十分可能。

ひとつの状態$x$に対し線形近似が一致$l(x) = f(x)$する確率はおよそ$(1 - \frac{1}{16}) \cdot (1 - \frac{1}{32}) + \frac{1}{16} \cdot \frac{1}{32} = \frac{233}{256} \approx 0.91$。
適当に128点の出力を選んできてすべて線形近似できている確率は$0.91^{128} \approx 5.85 \times 10^{-6}$と十分大きい。

### 詳細

体はすべて$GF(2)$である(ただしあまり重要でない)。
LFSRは内部状態としてvector $x$を持つ。
状態の更新は特定の形の線形関数$F$により$x \gets Fx$で、出力は線形とは限らない$f$を用いて$f(x)$となる。
なお更新は多項式$P$を用いて$x \gets 2x \bmod P$のようにも見れる(これも今回は使わない)。

$i$番目の出力<span>$y_i$</span>は<span>$y_i = f(F^{i+1}x)$</span>。
状態<span>$x = (x_0, x_1, \dots, x_{N - 1})$</span>は次元ごとに分解し<span>$x_j = (0, 0, \dots, 0, x_j, 0, 0, \dots, 0)$</span>のように見て<span>$x = \sum_{j \lt N} x_j$</span>と書ける。
$F$は定義より線形であり、さらに$f$も線形だったと仮定すると(記号を変えてvector $l = f$としておく) <span>$y_i = l^t F^{i+1} x$</span>である。
あるいは<span>$y_i = \sum_{j \lt N} (l^t F^{i+1})_j x_j$</span>。
これを複数本まとめて書き直せば
<div>$$
\begin{pmatrix}
    y_0 \\ y_1 \\ \vdots \\ y_{N-1}
\end{pmatrix} = \begin{pmatrix}
    l^t F \\
    l^t F^2 \\
    \vdots \\
    l^t F^N
\end{pmatrix} \begin{pmatrix}
    x_0 \\ x_1 \\ \vdots \\ x_{N-1}
\end{pmatrix}
$$</div> となる。
この式はまさに$y = Ax$の形をしていて(この$A$は$N \times N$の行列であることに注意)、単に$x = A^{-1}y$とすれば出力$y$から初期状態$x$が求まる。

今回の$l$は線形近似であって常に一致するとは限らない。つまり<span>$y_i \ne l^t F^{i+1}x$な行を含んでしまうと初期状態が求まらない。
これは近似が成功している番号<span>$i_0, i_1, \dots, i_{N-1}$</span>を選んで
<div>$$
\begin{pmatrix}
    y_{i_0} \\ y_{i_1} \\ \vdots \\ y_{i_{N-1}}
\end{pmatrix} = \begin{pmatrix}
    l^t F^{i_0 + 1} \\
    l^t F^{i_1 + 1} \\
    \vdots \\
    l^t F^{i_{N-1} + 1}
\end{pmatrix} \begin{pmatrix}
    x_0 \\ x_1 \\ \vdots \\ x_{N-1}
\end{pmatrix}
$$</div> としてやれば回避できる。
この番号<span>$i_0, i_1, \dots, i_{N-1}$</span>を選ぶのは乱択でよい。

## implementation

$10$分ぐらいで停止する。

``` python
#!/usr/bin/env sage
import ast
import random
from snurre128 import Snurre128

with open('keystream.txt') as fh:
    keystream = ast.literal_eval(fh.read())

mask = 528457622443627673964173138273112871261
nbits = int(mask).bit_length() - 1
K = GF(2)

# the update function
F = matrix(K, nbits)
for i in range(nbits):
    F[i, 0] = bool(mask & (1 << (nbits - i - 1)))
for i in range(nbits - 1):
    F[i, i + 1] = 1
print 'F =', F

# a linear-approximation of the output function
l = vector(K, nbits)
l[0] = l[1] = l[2] = l[31] = 1
print 'l =', l

l_pow_F = [ l * F ]
for y in range(len(keystream) - 1):
    l_pow_F += [ l_pow_F[y] * F ]

while True:
    # choose 128 points
    indices = range(len(keystream))
    random.shuffle(indices)
    A = matrix(K, [ l_pow_F[i]   for i in indices[: nbits] ])
    y = vector(K, [ keystream[i] for i in indices[: nbits] ])

    # estimate the key 
    try:
        x = A.solve_right(y)
    except ValueError:
        continue
    assert y == A * x
    key = ZZ(list(reversed(x)), 2)

    output = list(Snurre128(key).keystream(len(keystream)))
    print 'mismatch =', sum([ output[i] != keystream[i] for i in indices[: nbits] ])

    # check the validity
    if output == keystream:
        break
print 'key =', key  # 130306609594991829769917756515894243368
```
