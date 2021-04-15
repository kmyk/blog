---
redirect_from:
  - /writeup/algo/yukicoder/823/
layout: post
date: 2019-04-26T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# yukicoder No.823 Many Shifts Easy

## 問題

$N + 1$ 個のマスがあり、次のようである:

-   $0, 1, \dots, N$ と番号が振られている
-   最初すべてのマスには駒が置かれている

数列 $A$ であって次のようなものを考える:

-   長さ $|A| = K$
-   要素は整数で $1 \le A_i \le N$
-   要素はすべて異なる

数列 $A$ に対する点数を次のように定める:

1.  $i = 1, 2, \dots, K$ の順番に、マス $A_i$ にある駒をすべてマス $A_i−1$ に移す
2.  すべての駒についてその置かれているマスの番号を (重複なく) 考え、その総和が点数

条件を満たすすべての数列に対する点数の総和を $\bmod 10^9 + 7$ で求めよ。


## 考察

1.  とりあえず $N = K$ の場合を考えたい
1.  Many Shifts Hard があるということは、これらの問題の差が「Easy を解ける問題に変えている要素」である
1.  確率を使う系だったりしないか
1.  ~~重複を許して長さ $K = |A|$ を増やすと数列 $A$ ごとの期待値は $\frac{N}{2}$ に近付きそう~~
    -   問題を勘違い。行き先を $A_i$ で指定するとかではなく位置 $A_i$ のものをひとつ下にずらす
1.  元々 $x$ にあったものが $y \lt x$ に移って終了する確率を考えればよさそう
    -   $x, x - 1, \dots, y + 1$ がこの順で数列 $A$ に含まれ、その後ろには $y$ が出てこない場合がそれ
1.  元々 $x$ にあったものに対する移動が発生する回数の期待値を考えるのはどうか
    -   「その後ろには $y$ が出てこない」の条件が面倒そうなので、計測の位置を分配して解消したいため
1.  $d$ 回以上移動をする確率を考えたとき、不可能な場合を除いてその始点がどこかは影響しない
1.  数列 $A$ 中に列 $1, 2, \dots, l$ が含まれる確率は ${} _ K C _ l \cdot {} _ {N - l} P _ {K - l} / {} _ N P _ K$
1.  解けたはず
1.  誤読が判明: 点数計算のときに同じマスに複数個の駒が置かれていても $1$ 個分しか考えない
1.  各マスについて、そこが使われる期待値を求めたい
1.  あるマス $x$ に $x$ 由来の駒が残る確率と $x + 1$ 由来の駒が来る確率は独立ではない
1.  あるマス $x$ が使われるとは、$x$ が $A$ 中に出現しない、または $x$ が出現するがその後 $x + 1$ も出現する
1.  これやるだけじゃん (完)

## 解法

あるマス $x$ に駒がある状態で終了するのは「$x$ が $A$ 中に出現しない」または「$x$ が出現するがその後 $x + 1$ も出現する」場合のみ。
これらの確率は $1 - \frac{k}{n}$ と ${} _ K C _ 2 \cdot {} _ {N - 2} P _ {K - 2} / {} _ N P _ K$ であり、独立ではないが背反なので和を取ることができる。
確率は $x$ の値にほぼ依存せず、順列 ${} _ n P _ r$ の計算も $O(1)$ とみなせるので、全体での計算量は $O(1)$ となる。

## 反省

-   誤読
    -   サンプルを確認しましょう


## 誤読

多すぎて面白いのでまとめておく

<blockquote class="twitter-tweet" data-partner="tweetdeck"><p lang="ja" dir="ltr">ゆきこD、誤読ですね……</p>&mdash; リッキー (@rickytheta) <a href="https://twitter.com/rickytheta/status/1121783945912131584?ref_src=twsrc%5Etfw">April 26, 2019</a></blockquote>
<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">マスの値*駒の個数 だと思ってたよ...</p>&mdash; idsigma (@IKyopro) <a href="https://twitter.com/IKyopro/status/1121782338394845186?ref_src=twsrc%5Etfw">April 26, 2019</a></blockquote>
<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">D、同じマスに複数駒が残った時にそれぞれ加算するものと思い込んでて無限にサンプルとにらめっこしてた</p>&mdash; アルメリア (@armeria_betrue) <a href="https://twitter.com/armeria_betrue/status/1121781161749966848?ref_src=twsrc%5Etfw">April 26, 2019</a></blockquote>
<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">D 最初、マスにある駒の数で重み付けしたものの和が得点だと思ってた</p>&mdash; capra (@gzlcp) <a href="https://twitter.com/gzlcp/status/1121782198145703937?ref_src=twsrc%5Etfw">April 26, 2019</a></blockquote>
<blockquote class="twitter-tweet" data-conversation="none" data-cards="hidden" data-partner="tweetdeck"><p lang="ja" dir="ltr">誤読してた上にオーバーフローしてたので辛い</p>&mdash; fine@競プロ (@refine_P) <a href="https://twitter.com/refine_P/status/1121781818955485184?ref_src=twsrc%5Etfw">April 26, 2019</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">D各マス一回しか加算しないのマジ？解いてた問題違ったけど</p>&mdash; フェリン (@ferin_tech15) <a href="https://twitter.com/ferin_tech15/status/1121782071725191168?ref_src=twsrc%5Etfw">April 26, 2019</a></blockquote>


## リンク

-   <https://yukicoder.me/problems/no/823>
-   <https://yukicoder.me/submissions/343051>
