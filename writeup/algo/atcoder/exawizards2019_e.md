---
layout: post
date: 2019-11-01T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# エクサウィザーズ 2019: E - Black or White

## 考察過程

21:00 から

-   $\mathbb{F} _ {10^9 + 7}$ の分数なやつ。確率の収束を利用すると聞いてたけどできるのか？
-   Pascal の三角形ぽく $O(BW)$ で解けるのは自明。定数倍いけるか？ 無理そう
-   逆向きが同じ。つまり、$(B, W)$ 個あるところから食べて減らしていくのと、$(0, 0)$ 個あるところから作って増やしていくのと、どちらでも計算ができる
-   $i \ge 0$ 番目にチョコを食べるときそれが黒である確率 $$\mathrm{ans}(i) = \sum _ {b \le B \land w \le W \land b + w = B + W - i} p(b, w) \frac{b}{b + w} = \frac{\sum b p(b, w)}{B + W - i}$$
-   チョコが残り $(b, w)$ 個ある状態に到達する確率 $p(b, w)$ を考えたい
-   たとえば $(B, W) = (5, 4)$ のとき $p(3, 3)$ を考えれば、食べる順番は `BBW` `BWB` `WBB` いずれも等確率だと分かる。ここから $$p(b, w) = {} _ {B - b + W - w} C _ {B - b} \cdot \frac{B \cdot (B - 1) \cdot \dots \cdot (b + 1) \cdot W \cdot (W - 1) \cdot \dots \cdot (w + 1)}{(B + W) \cdot (B + W - 1) \cdot \dots \cdot (b + w + 1)}$$ が分かる
-   整理すると $$p(b, w) = {} _ {B - b + W - w} C _ {B - b} \cdot {} _ {B + W} C _ B \cdot {} _ {b + w} C _ b$$ あるいは $$p(b, w) = {} _ {B + W} C _ {b + w} \cdot {} _ B C _ b \cdot {} _ W C _ w$$ になる
-   $$p(b, w) \frac{b}{b + w} = {} _ {B - b + W - w} C _ {B - b} \cdot {} _ {B + W} C _ B \cdot {} _ {b + w - 1} C _ {b - 1}$$
-   この $\mathrm{ans}(i)$ 直接計算の方向は厳しくないか？
-   まじめに DP を考えましょう。でもできるのか？
-   直接計算と DP の両方をやりましょう。$(B, W)$ から $(0, 0)$ へではなく $(b, 0)$ から $(0, w)$ へ進むような線形の漸化式を立てて行列累乗で潰す感じができたらうれしい。できるかな？
-   $\mathrm{ans}(i) = \frac{1}{(B + W) \cdot \dots \cdot (B + W - i)} \cdot f(i)$ とすることにして分母を忘れ、 $f(i)$ だけ考えよう
-   ここで $f(i) = \sum g_i(b, w)$ とすると $$g_i(b, w) = {} _ {B + W} C _ {b + w} \cdot B \cdot (B - 1) \cdot \dots \cdot (b + 1) \cdot b \cdot W \cdot (W - 1) \cdot \dots \cdot (w + 1) = {} _ {B + W} C _ {B + W - i} \cdot \frac{B!}{(b - 1)!} \cdot \frac{W!}{w!}$$ である
-   つまり $h(b, w) = (b - 1)!^{-1} w!^{-1}$ についての漸化式を考えればよい
-   あるいは $\sum h(b, w)$ を求めればよい。$b + w - 1 = B + W - i - 1$ を使って $(b + w - 1)!^{-1}$ をあとから掛けることにすれば $\sum \frac{(b + w - 1)!}{(b - 1)! w!} = \sum {} _ {b + w - 1} C _ {b - 1}$ を求めればよい

22:06 終了。時間を投げ捨てれば解けるかもだが、効率が悪いため諦め

誤読していました。「黒か白を等確率で選び」の「等確率」とは、色についてのもの「黒を $50%$ かつ白を $50%$ で選び」であって、チョコについてのもの「黒白のチョコが $b + w$ 個あるときそれぞれを $\frac{1}{b + w}$ で選び」ではない。

再開です

-   これかなり単純に二項係数やるだけでは？
-   $B \times W$ の長方形からはみ出た部分を折り返すように潰すだけ
-   はみ出す部分は $i$ を増やしながら DP ぽく丁寧に管理することになった

23:06 AC

## メモ

-   教えてもらったが解いてなかったので
    <blockquote class="twitter-tweet" data-partner="tweetdeck"><p lang="ja" dir="ltr">「確率漸化式で考えたとき、n→∞ではこの確率はある値α（たとえば、初期状態における白玉と黒玉の個数の比　のようなもの）に収束するので、十分大きいnに対しては、確率をそのαであるとみなしても差し支えない」という解法などはどうでしょうか　エクサウィザーズのEの嘘解法でした</p>&mdash; 飯香 (@iicafiaxus) <a href="https://twitter.com/iicafiaxus/status/1190205050020196352?ref_src=twsrc%5Etfw">November 1, 2019</a></blockquote>
    <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
    <blockquote class="twitter-tweet" data-conversation="none" data-cards="hidden" data-partner="tweetdeck"><p lang="ja" dir="ltr">すみませんだいぶ言葉が足りなかったです。この問題は、その嘘解法を塞ぐために、「許容誤差は絶対誤差または相対誤差が〜」という出題形式ではなく、有理数で求めさせるようにしているのだ　という説明を見ました</p>&mdash; 飯香 (@iicafiaxus) <a href="https://twitter.com/iicafiaxus/status/1190291730496548864?ref_src=twsrc%5Etfw">November 1, 2019</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

-   誤読した結果も面白い問題になってる気がする。しかしちょっと実装重めではある
-   元の問題は良い問題だが、自明なので面白いとか面白くないとかではない

## リンク

-   <https://atcoder.jp/contests/exawizards2019/tasks/exawizards2019_e>
-   提出: <https://atcoder.jp/contests/exawizards2019/submissions/8241456>
