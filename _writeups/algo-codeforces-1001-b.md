---
redirect_from:
  - /writeup/algo/codeforces/1001-b/
layout: post
date: 2018-07-02T22:17:32+09:00
tags: [ "competitive", "writeup", "codeforces", "q-sharp-contest", "quantum-computing" ]
"target_url": [ "http://codeforces.com/contest/1001/problem/B", "http://takeo1116.sakura.ne.jp/cfqs01b.html" ]
---

# Codeforces Microsoft Q# Coding Contest - Summer 2018 - Warmup: B. Generate Bell state

## 注意

この記事は[この解説](http://takeo1116.sakura.ne.jp/cfqs01b.html)の補助資料

## 予備知識 / 補足説明

$$
\def\bra#1{\mathinner{\left\langle{#1}\right|}}
\def\ket#1{\mathinner{\left|{#1}\right\rangle}}
\def\braket#1#2{\mathinner{\left\langle{#1}\middle|#2\right\rangle}}
$$
複数の関連したqubitsの状態はentanglement ([量子もつれ状態](https://ja.wikipedia.org/wiki/%E9%87%8F%E5%AD%90%E3%82%82%E3%81%A4%E3%82%8C))の存在によって単純ではない。
そこで、qubitそれぞれの状態を$n$つ組として並べるのではなくて、qubits全体というひとつの対象に対し状態を与える。
例えば$3$個のqubitsがあるなら$\ket{000}, \ket{001}, \ket{010}, \ket{011}, \dots, \ket{111}$まで$8 = 2^3$個の基底状態を用意し、ひとつの場合と同様に線形結合する。
このようにすることで例えば $\ket{B_0} = \frac{1}{\sqrt{2}} \left( \ket{00} + \ket{11} \right)$ つまり「どちらの基底状態かは分からないけどふたつのqubitsの状態は同じだよ」を表現できる。

これらの状態に使うベクトル空間はテンソル空間、特に単独のqubitのためのベクトル空間の$n$個のテンソル積であるようなものとする。
これにより<span>$\ket{101} = \ket{1}_0 \otimes \ket{0}_1 \otimes \ket{1}_2$</span>などと書ける。
テンソル積は双線型なので<span>$$\ket{+0} = \ket{+}_0 \otimes \ket{0}_1 = \left( \frac{1}{\sqrt{2}} \begin{pmatrix} 1 \\ 1 \end{pmatrix} \right) \otimes \begin{pmatrix} 1 \\ 0 \end{pmatrix} = \frac{1}{\sqrt{2}} \left( \begin{pmatrix} 1 \\ 1 \end{pmatrix} \otimes \begin{pmatrix} 1 \\ 0 \end{pmatrix} \right) = \frac{\ket{00} + \ket{10}}{\sqrt{2}}$$</span>などとなることにも注意。

次にgatesがどうなるのかについて。
これは線型写像のテンソル積になる。
例としてふたつのqubitsが状態$\ket{B_0}$にあるときに$1$番目のものをNOT gate $$X = \begin{pmatrix} 0 & 1 \\ 1 & 0 \end{pmatrix}$$に通すことを考えよう。
単位行列$I$を持ってきて$I \otimes X$が目的の操作となる。
$(A \otimes B)(x \otimes y) = Ax \otimes By$なので、状態は<span>$$(I \otimes X)\ket{B_0} = \frac{1}{\sqrt{2}} \left(( \ket{0}_0 \otimes X\ket{0}_1) + (\ket{1}_0 \otimes X\ket{1}_1) \right) = \frac{1}{\sqrt{2}} \left( \ket{01} + \ket{10} \right) = \ket{B_2}$$</span>に移る。

## 参考

-   [テンソル積 - Wikipedia](https://ja.wikipedia.org/wiki/%E3%83%86%E3%83%B3%E3%82%BD%E3%83%AB%E7%A9%8D)
