---
redirect_from:
  - /writeup/algo/atcoder/abc155/
layout: post
date: 2020-02-17T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# AtCoder Beginner Contest 155

## D - Pairs

積が $x$ 未満となる組の個数 $f(x)$ を二分探索で求める関数を書き、これを元にして答えを二分探索。$O(N \log N \log \max_i A_i)$。想定は尺取り法で $O(N \log \max_i \vert A_i \vert)$ らしい。

思い付くためには、次のふたつを考えると楽:

1.  入力 $A_i$ に負数が含まれるため難しい。ではすべてが非負だとすれば解けるか？
1.  $\frac{N(N-1)}{2}$ 個あるすべての組を考えるから難しい。では $A_1$ と $(A_2, A_3, \dots)$ のどれかという $N - 1$ 個の組だけでよければ解けるか？

### 機械解法

(1.) から (2.) への変形はちょっとギャップある。(2.) から (5.) まではやるだけ

1.  問題文を翻訳: the $K$-th number of $\lbrace\lbrace A_i A_j \mid i \lt j \rbrace\rbrace$
1.  これは次を求めるのと同じだと見抜く: $\min \left\lbrace x \mid \unicode{35} \lbrace (i, j) \mid i \lt j \land A_i A_j \le x \rbrace \ge K \right\rbrace$
1.  式変形: $\min \left\lbrace x \mid \sum_j \unicode{35} \lbrace i \lt j \mid A_i A_j \le x \rbrace \ge K \right\rbrace$
1.  式変形: $\min \left\lbrace x \mid (\sum _ {A_j \ge 0} \unicode{35} \lbrace i \lt j \mid A_i \le x / A_j \rbrace) + (\sum _ {A_j \lt 0} \unicode{35} \lbrace i \lt j \mid A_i \ge x / A_j \rbrace) \ge K \right\rbrace$
1.  これは $O(N \log N \log \max_i \vert A_i \vert)$

## E - Payment

下から桁DP。$O(\log N)$。

「$N$ の $i$ 桁目以下 (つまり $N \bmod 10^i$) をちょうど払うときの紙幣の枚数」および「$N$ の $i$ 桁目以下の補数 (つまり $10^i - (N \bmod 10^i)$) をちょうど払うときの紙幣の枚数」を同時に求める。
ここで補数が $10^i - (N \bmod 10^i) - 1$ ではないことに注意が必要。つまり最下位桁だけ特別扱いする。

漸化式が線形なので、$N$ の $10$ 進数展開が周期的だったなら行列累乗もできる。

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">E問題、お釣りを受け取らなければ答えは常に1なので、貧困が悪い。</p>&mdash; 宇宙ツイッタラーX (@kenkoooo) <a href="https://twitter.com/kenkoooo/status/1229041341054611457?ref_src=twsrc%5Etfw">February 16, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

これすき

## メモ

-   D, E ともにバグらせた
-   F は分からなかった (時間があれば嘘解法を無理矢理はあったかも？)

## リンク

-   <https://atcoder.jp/contests/abc155>
-   D 実装: <https://atcoder.jp/contests/abc155/submissions/10151716>
-   E 実装: <https://atcoder.jp/contests/abc155/submissions/10157591>
