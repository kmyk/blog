---
layout: post
date: 2019-08-31T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# Chokudai Contest 004: A - マス目に数を書き込む問題

## 問題

$n \times n$ のマス目に $1 \sim 9$ の数を書き込む。
横か縦一列に見て和が $B_1, B_2, B_3$ のいずれかな区間があれば $B_i$ 点貰える。
点数を最大化せよ。

## 解法

ふつうに焼きなまし。
適当 1 点更新が強く、近傍の改善もしたけどはあまり有効でなかった。
スコア差分の計算はしゃくとりぽくやる。
試行回数は $2 \times 10^6$ ぐらい。

他の人の解法を見るに、ひたすら高速化するだけの勝負だったぽい。
「$1$ 回の試行」の定義にもよるがとりあえず $10^7$ 回に乗せる必要はありそう。
$8$ 時間や $1$ 週間あれば天才が生えてくる可能性はあるが $2$ 時間だと初手愚直をひたすら定数倍が最適ムーブとなる。

## リンク

-   問題ページ: <https://atcoder.jp/contests/chokudai004/tasks/chokudai004_a>
-   自分の提出: <https://atcoder.jp/contests/chokudai004/submissions/7232262>
-   agw さん Togetter: <https://togetter.com/li/1397914>

## 他の人の解法

### ats5515 さん: 1652578 点 1 位

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">普通に焼きなましました。近傍は一点更新、長さが10より大きい区間は無視して影響ある区間すべてを愚直に計算した。</p>&mdash; ATS (@ats5515) <a href="https://twitter.com/ats5515/status/1167801247899897856?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-conversation="none"><p lang="ja" dir="ltr">焼きなましの温度は30から10に線形に減らした。<br>主に近傍選択を試すのに時間を費やしたけど一番単純な方法（1点を別の数に変える）が一番良かった。<br>正直どのへんで差がついているのかわからないけど温度管理なのかな</p>&mdash; ATS (@ats5515) <a href="https://twitter.com/ats5515/status/1167804182088183808?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

提出コードを借りてきて見てみると $2 \times 10^7$ 回試行があるので、彼の勝因は高速化ぽい？

### math さん: 1631928 点 2 位

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">1マス選んで値をランダムに変える焼きなまし。試行回数は1.5 * 1e7 で 1631928。試行回数を10倍すれば1650000は間違いなく超えられるが…</p>&mdash; まーす (@__math) <a href="https://twitter.com/__math/status/1167799770590507009?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">main - Ans::calcDiffの10.74%のうちの大半がSAの計算なので、ここを高速化するだけでも試行回数は5%くらい増やせて、この程度のスコア差だとこれでも効いてくる <a href="https://t.co/p2P8zEpGvX">pic.twitter.com/p2P8zEpGvX</a></p>&mdash; まーす (@__math) <a href="https://twitter.com/__math/status/1167801282498711552?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

### tanzaku さん: 1625536 点 3 位

### gasin さん: 1609480 点 4 位

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">1点をランダムな値に書き換えるシンプルな焼きなましをしていた</p>&mdash; гасин (@_gacin) <a href="https://twitter.com/_gacin/status/1167799690030534656?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

試行回数は $5 \times 10^6$ らしい

### sumoooru さん: 1605376 点 5 位

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">Chokudai Contest 004 お疲れ様でした。多分５位<br>やったこと<br>ある場所の数字を変えて、たまにその隣の数字も先の増分だけ減らすような焼きなまし。試行回数2.5M回くらい<br>スコアの差分は縦横の尺取り法</p>&mdash; sumoru (@sumoooru) <a href="https://twitter.com/sumoooru/status/1167801069746843648?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">TL見て焼きなましの温度を30 -&gt; 0 から 30 -&gt; 10にしたら１万点くらい良くなった <a href="https://twitter.com/hashtag/chokudai_004?src=hash&amp;ref_src=twsrc%5Etfw">#chokudai_004</a></p>&mdash; sumoru (@sumoooru) <a href="https://twitter.com/sumoooru/status/1167805884061249537?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

同じことやってる。温度調節での 1 万点は誤差な気がするが

### koyumeishi さん: 1591239 点 6 位

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">雑にビームサーチしただけ。 評価関数工夫してる暇なかった (多分焼いた方がいい気がする)</p>&mdash; koyumeishi (@koyumeishi_) <a href="https://twitter.com/koyumeishi_/status/1167799572321595392?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">ビームサーチ、<br>* 普通に左上から<br>* 左上から互い違い(ヘビ)<br>* 左上からのマンハッタン距離順<br>の3種類走査順試したけど、ヘビが一番強かったっぽい (評価関数的にそれはそう)</p>&mdash; koyumeishi (@koyumeishi_) <a href="https://twitter.com/koyumeishi_/status/1167803607112024069?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-conversation="none"><p lang="ja" dir="ltr">ビーム幅は 4000-6000 ぐらいでした (結構時間に余裕はあって 8000 ぐらいにもできたんだけど、いつもの良い状態が蹴りだされるアレでスコアが下がりそうなのでほげ (提出制限もあったので試してない))</p>&mdash; koyumeishi (@koyumeishi_) <a href="https://twitter.com/koyumeishi_/status/1167807546108735488?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

ビームサーチを 6 位に乗せれるのガチプロって感じがする。すごい

### hos_lyric  さん: 1587092 点 7 位

### betrue12 さん: 1586162 点 8 位

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">1点更新の焼きなましで、累積和を使うと1回あたり再計算O(N^2)なんだけど、更新前も更新後もB3を超えるようになったらそれより長い区間は無視してよくて、それをやると反復回数をかなり稼げた</p>&mdash; アルメリア (@armeria_betrue) <a href="https://twitter.com/armeria_betrue/status/1167800464726867969?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

### tomerun さん: 1581564 点 9 位

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">ランダムな点を別の数に変えるSA。変化させた点の周囲だけ評価。縦方向の評価でキャッシュ当たりやすいように90度回転させた盤面も持つ。変化先の値にB3-B2やB2-B1が出やすいようにする（効果があるかは不明） <a href="https://twitter.com/hashtag/chokudai_004?src=hash&amp;ref_src=twsrc%5Etfw">#chokudai_004</a></p>&mdash; tomerun (@tomerun) <a href="https://twitter.com/tomerun/status/1167800785045864449?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

キャッシュのために $90$ 度回転かしこいけど、 $30 \times 30$ なので $900$ byte だし気にする必要なさそうに見える？
これ見て「そういえば盤面を `int` で持ってたけど `char` にしたら速くなるかな」と思ってやってみたけどほぼ変わらなかった。

### zaki_ さん: 1573465 点 10 位


### EvbCFfp1XB さん: 1557634 点 16 位

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">Chokudai Contest 004 はランダムに数字を変えるSAです。 <a href="https://t.co/DX7FQ26Btj">pic.twitter.com/DX7FQ26Btj</a></p>&mdash; EvbCFfp1XB (@EvbCFfp1XB) <a href="https://twitter.com/EvbCFfp1XB/status/1167803180844896257?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

$2$ 時間コンでビジュアライザ書いて本体も間に合わせるのえらい

### snuke さん: 1512698 点 28 位

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">適当にやきなました。（マスを変える、隣接を+1,-1する、2*2を+1,-1,-1,+1）<br>これ以上どうやって伸ばすのか分からず、画像作って眺めてた（何も分からず）<a href="https://twitter.com/hashtag/chokudai004?src=hash&amp;ref_src=twsrc%5Etfw">#chokudai004</a> <a href="https://t.co/nS6brEjF2S">pic.twitter.com/nS6brEjF2S</a></p>&mdash; ꑄ꒖ꐇꌅꏂ🐈 (@snuke_) <a href="https://twitter.com/snuke_/status/1167799892422451200?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

ビジュアライズで時間溶かしてたでしょ感ある
