---
layout: post
date: 2019-11-09T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# AtCoder 第二回全国統一プログラミング王決定戦予選

全体 $233$ 位かつ日本 $166$ 位なので予選通過はしましたが、冷えです

## A - Sum of Two Integers

はい。$\Theta(1)$。しかしなんだか不安だったので愚直 $\Theta(N)$ を書いた。

## B - Counting of Trees

ありがち。$\Theta(N)$ です。$D_1 \ne 0$ とか $D_2 = 0$ がコーナーになりそう。

## C - Swaps

分からない。しかしなぜか AC はできてしまった

## D - Shortest Path on a Line

これはかんたん。辺の張り方から、いつでも頂点を $i + 1 \to i$ と後戻りしてよいことが分かる。
すると $L_i \to R_i$ というコスト $C_i$ の辺を $1$ 本張るだけで十分になり、Dijkstra 法などで $O((N + M) \log N)$ で解ける。

### メモ

セグ木とかでも解けるぽい:

<blockquote class="twitter-tweet" data-partner="tweetdeck"><p lang="ja" dir="ltr">D問題さん、区間min, 区間chminでぶん殴ったんですけど想定解多分違いますよね……</p>&mdash; 竹雄 (@takeo1116) <a href="https://twitter.com/takeo1116/status/1193166772104359936?ref_src=twsrc%5Etfw">November 9, 2019</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-partner="tweetdeck"><p lang="ja" dir="ltr">D、こんなのセグ木に決まってるだろと言いながら証明をするとできるので貼ってしまった（正当性示したらdijkstraできるのはそれはそうなんですが）</p>&mdash; beet (@beet_aizu) <a href="https://twitter.com/beet_aizu/status/1193168970162962432?ref_src=twsrc%5Etfw">November 9, 2019</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-partner="tweetdeck"><p lang="ja" dir="ltr">Dは (コスト, 区間) を優先度キューに突っ込んでmin取るだけ</p>&mdash; くりんぺっと (@climpet) <a href="https://twitter.com/climpet/status/1193168516469293062?ref_src=twsrc%5Etfw">November 9, 2019</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-partner="tweetdeck"><p lang="ja" dir="ltr">セグ木みたいにして頂点張るのは思いついたけど面倒でやめたな</p>&mdash; もやし (@oreha_senpai) <a href="https://twitter.com/oreha_senpai/status/1193171287184556032?ref_src=twsrc%5Etfw">November 9, 2019</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>


## E - Non-triangular Triplets

分からない。$c = (K + 2N, K + 2N + 1, \dots, K + 3N - 1)$ としてよくて、このことから \sum c - \sum a - \sum b = N^2 - NK - \frac{N(N - 1)}{2}$ であり $\sum a + \sum b \le \sum c \iff 2K \le N + 1$ が言える。この必要条件はおそらく十分条件なのですが……

## リンク

-   <https://atcoder.jp/contests/nikkei2019-2-qual>
