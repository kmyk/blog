---
redirect_from:
  - /writeup/algo/hackerrank/nada1024-2019/
layout: post
date: 2019-10-24T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# 灘校創立記念日コンテスト

## C. Extrication

両側から BFS するだけ。$O(HW)$

(実装省略)

## D. 5757757577

### 問題

正整数 $N, P$ が与えられる。次のような $k$ の存在を判定し、存在するなら構成せよ:  $N$ を $10$ 進数展開し $k$ 回繰り返してできる正整数が $P$ の倍数である。

### 考察過程

-   $N$ の桁数 $d$ に対し $f = 10^d x + N \in \mathbb{Z}/P\mathbb{Z}[x]$ とおく。
    このとき関数合成による $f^k = \underbrace{f \circ f \circ \dots \circ f} _ {k ~ \text{times}}$ の定数項が $0$ になるような $k$ を求めればよい。
-   形が $10^d x + N$ (ただし $N \lt 10^d$) に制限されてるし実は愚直が通ったりしないか？ → しませんでした
-   $$\left(\begin{matrix} f^{k + 1}(x) \\ 1 \end{matrix}\right) = \left(\begin{matrix} 10^d & N \\ 0 & 1 \end{matrix}\right) \left(\begin{matrix} f^k(x) \\ 1 \end{matrix}\right)$$ になっています。この行列 $A$ が正則かどうか見れば？ 離散対数問題にして $k$ が出る？ そうでもなさそう
-   系列は $0, b, (a + 1)b, (a^2 + a + 1)b, (a^3 + a^2 + a + 1)b, \dots$ と続く。$(\dots + a^2 + a + 1)b \equiv 0 \pmod{p}$ を考えると、$b, p$ が互いに素なら $\dots + a^2 + a + 1 \equiv 0 \pmod{p}$ を考えて十分。ところで $a = 10^d$ なのでかなり規則的
-   つまり $d$ は $N$ と無関係だとすれば $N = 1$ を仮定してよい
-   $(a - 1)(a^k + \dots + a^2 + a + 1) = a^{k + 1} - 1$ である。$a^{k + 1} \equiv 1 \pmod{p}$ となるような $k$ を探せばよい
-   なぜか WA ですが……
-   ところで $P \le 10^{12}$ の制約ですが $\mathbb{Z}/P\mathbb{Z}$ の乗算はなしで解けるということか？ それとも `__int128` か？
-   ちゃんと Euler's $\phi$ を計算したりしたら AC が増えたが、まだ WA は残る。なぜ
-   submit debug により WA はすべて間違えて $-1$ を吐いている場合であることを確認した
-   $(a - 1)^{-1}$ の分を忘れていそう
-   だめです。なぜ

## E. Odd Network

### 問題

単純無向グラフ $G = (V, E)$ が与えられる。それぞれの頂点 $v \in V$ には重み $p_v \in 2$ が付いている。
辺集合を一様ランダムに選び、それぞれの頂点の次数の偶奇が重み $p_v$ に一致するようなものだけを考えたとき、その辺集合の要素数の期待値を求めよ。

## F. ひどいこと

### 考察過程

-   自明では？ って思ったら最大化問題だった。それはそう
-   石にする要素の高さは昇順でなければならない
-   並べ替えのコストは単にバブルソートする感じで見ればよい
-   ある要素を石にしたときに得られる点数は、それより左の要素であってそれより高いものの数とそれより右の要素であってそれより低いものの数から分かる。石にされた要素どうしは必ずソート済みであるので、具体的にどれを石にしたか/石にする予定かは気にしなくてよい
-   区間中の $X$ より小さい要素の数を数えるのが $O(\log N)$ でできてほしい。まあこれはできるでしょ。ライブラリ持ってないけどこれ: <https://judge.yosupo.jp/problem/rectangle_sum>
-   最後に使った要素の位置を状態としても全体で $O(N^2 \log N)$ になりそう。これは最後に使った要素の高さを状態にすべきで、これなら $O(N \log N)$ になるはず

(実装省略)

## メモ

<blockquote class="twitter-tweet" data-partner="tweetdeck"><p lang="ja" dir="ltr">D: 離散対数<br>E: 橋以外は全部1/2</p>&mdash; よすぽ (@yosupot) <a href="https://twitter.com/yosupot/status/1187369813716459521?ref_src=twsrc%5Etfw">October 24, 2019</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-partner="tweetdeck"><p lang="ja" dir="ltr">NDお誕生日コンテストなのでお誕生日攻撃が想定だとエスパーすることができる</p>&mdash; きゅうり (@kyuridenamida) <a href="https://twitter.com/kyuridenamida/status/1187369200022634497?ref_src=twsrc%5Etfw">October 24, 2019</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-partner="tweetdeck"><p lang="ja" dir="ltr">灘コン<br>D: 普通に解けなかった (素冪が入るとき)<br>E: 対称差を取るやつ、e と ord[e] を書き間違えて無限時間溶かした<br>F: LIS → A は distinct ではありません、人生終了</p>&mdash; 熨斗袋 (@noshi91) <a href="https://twitter.com/noshi91/status/1187368875454849024?ref_src=twsrc%5Etfw">October 24, 2019</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

至る所が `__int128` になったり $10^{17} - 1$ の大きい素因数にも殺されたりもするらしいです


## リンク

-   <https://www.hackerrank.com/contests/nada1024-2019>
