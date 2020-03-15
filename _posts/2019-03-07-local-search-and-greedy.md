---
category: blog
layout: post
redirect_from:
    - "/blog/2019/03/06/local-search-and-greedy/"
date: "2019-03-07T00:00:00+09:00"
edited: "2019-03-08T03:00:00+09:00"
tags: [ "competitive", "marathon-match", "local-search", "greedy", "hill-climing", "simulated-annealing", "beam-search" ]
---

# 貪欲法、山登り法、焼きなまし、ビームサーチ、これらの間の関係について

## 概要

マラソンマッチにおける有力なアルゴリズムとして焼きなましとビームサーチがある。
たいていの問題においてこのどちらかのうちより適切な方を実装すれば上位が得られることや、性質や実装の仕方が異なることから、これらの関係は二項対立のようにして理解されている。
しかしこのふたつのアルゴリズムがどちらも貪欲法の延長にあることも知られている。

この記事では、貪欲法を中心に整理して焼きなましとビームサーチの二項対立の構図は適切でないことを示す。
特に、これらの差異が状態空間の間のグラフが有向であるか無向であるかのみであることを明らかにし、下図のような形で整理する。
またその系として、焼きなましとビームサーチの間で互いに知見を流用できることを説明する。

<?xml version="1.0" encoding="UTF-8"?>
<svg width="602" height="602" version="1.1" viewBox="-.5 -.5 602 602" xmlns="http://www.w3.org/2000/svg">
<rect x=".25062" y=".25062" width="300.25" height="600.5" fill="none" pointer-events="none" stroke="#000" stroke-dasharray="4.50374064, 4.50374064" stroke-width="1.5012"/>
<rect x="300.5" y=".25062" width="300.25" height="600.5" fill="none" pointer-events="none" stroke="#000" stroke-dasharray="4.50374064, 4.50374064" stroke-width="1.5012"/>
<text x="13.529704" y="30.110167" fill="#000000" font-family="sans-serif" font-size="30.025px" letter-spacing="0px" stroke-width=".75062" word-spacing="0px" style="line-height:1.25" xml:space="preserve"><tspan x="13.529704" y="30.110167" font-size="20.017px" stroke-width=".75062">状態のグラフが有向</tspan></text>
<text x="407.45096" y="31.439451" fill="#000000" font-family="sans-serif" font-size="30.025px" letter-spacing="0px" stroke-width=".75062" word-spacing="0px" style="line-height:1.25" xml:space="preserve"><tspan x="407.45096" y="31.439451" font-size="20.017px" stroke-width=".75062">状態のグラフが無向</tspan></text>
<path d="m121.37 283.46 2.2068-11.53 2.5822 5.2694 5.7648 1.1109z" pointer-events="none" stroke="#000" stroke-miterlimit="10" stroke-width="1.5012"/>
<path d="m479.55 283.52-10.824-4.5638 5.7047-1.4112 2.2669-5.4195z" pointer-events="none" stroke="#000" stroke-miterlimit="10" stroke-width="1.5012"/>
<path d="m209.33 478.68-10.824-4.5638 5.7047-1.4112 2.2669-5.4195z" pointer-events="none" stroke="#000" stroke-miterlimit="10" stroke-width="1.5012"/>
<path d="m391.67 478.68 2.8524-11.394 2.2669 5.4195 5.7047 1.4112z" pointer-events="none" stroke="#000" stroke-miterlimit="10" stroke-width="1.5012"/>
<rect x="120.35" y="89.635" width="360.3" height="90.075" rx="13.511" ry="13.511" fill="#fff" pointer-events="none" stroke="#000" stroke-width="1.5012"/>
<text x="211.22034" y="142.98514" fill="#000000" font-family="sans-serif" font-size="30.025px" letter-spacing="0px" stroke-width=".75062" word-spacing="0px" style="line-height:1.25" xml:space="preserve"><tspan x="220.22034" y="145" stroke-width=".75062">貪欲 / 山登り</tspan></text>
<rect x="11.735" y="284.8" width="217.23" height="90.075" rx="16.292" ry="13.511" fill="#fff" pointer-events="none" stroke="#000" stroke-width="1.6485"/>
<text x="28.197054" y="341.95129" fill="#000000" font-family="sans-serif" font-size="30.025px" letter-spacing="0px" stroke-width=".75062" word-spacing="0px" style="line-height:1.25" xml:space="preserve"><tspan x="30" y="341.95129" stroke-width=".75062">ビームサーチ</tspan></text>
<rect x="372.03" y="284.8" width="217.23" height="90.075" rx="16.292" ry="13.511" fill="#fff" pointer-events="none" stroke="#000" stroke-width="1.6485"/>
<text x="426.12924" y="342.58899" fill="#000000" font-family="sans-serif" font-size="30.025px" letter-spacing="0px" stroke-width=".75062" word-spacing="0px" style="line-height:1.25" xml:space="preserve"><tspan x="410" y="342.58899" stroke-width=".75062">焼きなまし</tspan></text>
<rect x="120.35" y="479.96" width="360.3" height="90.075" rx="13.511" ry="13.511" fill="#fff" pointer-events="none" stroke="#000" stroke-width="1.5012"/>
<text x="30.747864" y="517.32208" fill="#000000" font-family="sans-serif" font-size="30.025px" letter-spacing="0px" stroke-width=".75062" word-spacing="0px" style="line-height:1.25" xml:space="preserve"><tspan x="30.747864" y="517.32208" stroke-width=".75062">ビームサーチ + 評価関数に乱数</tspan></text>
<text x="271.16525" y="554.30933" fill="#000000" font-family="sans-serif" font-size="30.025px" letter-spacing="0px" stroke-width=".75062" word-spacing="0px" style="line-height:1.25" xml:space="preserve"><tspan x="240" y="554.30933" stroke-width=".75062">焼きなまし + 状態プール</tspan></text>
<path d="m198.42 182.71-72.255 94.488" fill="none" pointer-events="none" stroke="#000" stroke-miterlimit="10" stroke-width="1.5012"/>
<text x="68.37291" y="236.72882" fill="#000000" font-family="sans-serif" font-size="30.025px" letter-spacing="0px" stroke-width=".75062" word-spacing="0px" style="line-height:1.25" xml:space="preserve"><tspan x="68.37291" y="236.72882" font-size="20.017px" stroke-width=".75062">状態の集合を保持</tspan></text>
<path d="m390.57 179.71 83.86 97.836" fill="none" pointer-events="none" stroke="#000" stroke-miterlimit="10" stroke-width="1.5012"/>
<text x="374.47458" y="239.27966" fill="#000000" font-family="sans-serif" font-size="30.025px" letter-spacing="0px" stroke-width=".75062" word-spacing="0px" style="line-height:1.25" xml:space="preserve"><tspan x="374.47458" y="239.27966" font-size="20.017px" stroke-width=".75062">確率的に採用</tspan></text>
<path d="m480.65 374.87-83.86 97.836" fill="none" pointer-events="none" stroke="#000" stroke-miterlimit="10" stroke-width="1.5012"/>
<text x="371.00357" y="428.0462" fill="#000000" font-family="sans-serif" font-size="30.025px" letter-spacing="0px" stroke-width=".75062" word-spacing="0px" style="line-height:1.25" xml:space="preserve"><tspan x="371.00357" y="428.0462" font-size="20.017px" stroke-width=".75062">状態の集合を保持</tspan></text>
<g transform="matrix(.75062 0 0 .75062 -.12469 -.12469)">
<path d="m160.5 499.58 111.72 130.34" fill="none" pointer-events="none" stroke="#000" stroke-miterlimit="10" stroke-width="2"/>
<text x="141.56317" y="573.73865" fill="#000000" font-family="sans-serif" font-size="40px" letter-spacing="0px" word-spacing="0px" style="line-height:1.25" xml:space="preserve"><tspan x="141.56317" y="573.73865" font-size="26.667px">確率的に採用</tspan></text>
</g>
</svg>


## 準備

### 最適化問題

#### 形式化

この記事では最小化問題だけを取り扱う。
つまり、集合 $$X$$ と関数 $$f : X \to \mathbb{R}$$ が与えられたときに $$\arg\min _ {x \in X} f(x)$$ を求めることを考える。
なお、この $$X$$ を解空間、その要素 $$x \in X$$ を解、$$f$$ を目的関数と呼ぶ。

### 貪欲法

#### 非形式的な説明

貪欲法は例えば [貪欲法 - Wikipedia](https://ja.wikipedia.org/wiki/%E8%B2%AA%E6%AC%B2%E6%B3%95)<sup>[archive.org](https://web.archive.org/web/20190306163053/https://ja.wikipedia.org/wiki/%E8%B2%AA%E6%AC%B2%E6%B3%95)</sup> では次のように説明されている:

>   このアルゴリズムは問題の要素を複数の部分問題に分割し、それぞれを独立に評価を行い、評価値の高い順に取り込んでいくことで解を得るという方法である。

貪欲法とは、局所的な評価関数に従い先読みをせずに解を構築するようなアルゴリズムの総称と言える。
コストパフォーマンスのよい順にソートして順番に使うナップサック問題への貪欲法、などが典型的である。

ただし要素の評価やソートは必ずしも事前にすべて済ませる必要はない。
つまり評価値を現在までの選択に依存して定めてしまってもよい。
また、最適解が必ず求まるものには限定していないことにも注意してほしい<sup><a title="厳密解を得られる場合についてはモトロイドを用いた理解が知られている">note</a></sup>。

#### 形式化

貪欲法は次のようなものであると理解できる。
まず、問題に対し有向グラフ $$(V, E)$$ と関数 $$g : V \to \mathbb{R}$$ を適切に選ぶ。
$$v \in V$$ に対し $$N(v) = \{ w \in V \mid (v, w) \in E \}$$ と定義し、さらに $$v \in V$$ が $$N(v) = \emptyset$$ ならば $$v \in X$$ である (あるいはそう見做せる<sup><a title="この部分には「たとえば実数の 3 と整数の 3 は同じものだろうか？」などのような難しさが隠れている">note</a></sup>) と仮定する。
また、 $$v^\ast = \arg\min _ {w \in N(v)} g(w)$$ と定義する。
適切な点 $$v = v_0 \in V$$ から始めて $$N(v) \ne \emptyset$$ な限り $$v \gets v^\ast$$ と更新することを繰り返し、最終的に得られた $$v$$ に対し $$h(v)$$ が問題に対する解である。

なお、この $$V$$ を状態空間、その要素 $$v \in V$$ を状態、$$E$$ あるいは $$e \in E$$ を遷移、$$g$$ を評価関数と呼ぶ。
さらに $$N(v)$$ あるいはその要素 $$w \in N(v)$$ を状態 $$v$$ の近傍と呼ぶ。
$$N(v) = \emptyset$$ な $$v \in V$$ を $$X$$ に埋め込む操作が非自明なときや陽に扱いたいとき、これを解釈関数 $$h : V \to X$$ と呼ぶ。

#### 例: 巡回セールスマン問題

巡回セールスマン問題を考えよう。
$$n$$ 頂点とする。
関数 $$d : n \times n \to \mathbb{R}$$ が与えられる。
解空間 $$X$$ は $$n$$ 要素の順列全体なので[置換群](https://ja.wikipedia.org/wiki/%E5%AF%BE%E7%A7%B0%E7%BE%A4) $$\mathfrak{S} _ n$$ であり、目的関数 $$f(\sigma) = \sum _ {i \lt n - 1} d(\sigma(i), \sigma(i + 1))$$ となる。

$$|X| = n!$$ であるのでこれは大きすぎる。
そこで順列を前から $$1$$ 要素づつ構築していくことを考える。
特に、頂点 $$0$$ から初めて、まだ訪れていない頂点の中で最も近いものを訪れることを繰り返せば、これは $$O(n^2)$$ でそれなりの解が得られるだろう。

これは上記の形式化において、状態空間を $$V = \{ \sigma : k \rightarrowtail n \mid k \le n \land \sigma \text{は単射} \}$$ とおき、遷移を $$E = \{ (\sigma, \sigma ^ a) \mid \sigma, \sigma ^ a \in V \}$$ とし、評価関数を $$g(\sigma) = \sum _ {i \lt k - 1} d(\sigma(i), \sigma(i + 1))$$ としたものである。


### ビームサーチ

#### 非形式的な説明

貪欲法は見ている範囲の状態のうち「最も良いものだけ」を記憶し利用していた。
ビームサーチとは、これを「良い順に $$k$$ 個まで」と緩和することでさらに良い解を得ようとするものである。

#### 形式化

貪欲法においては、状態 $$v = v_0 \in V$$ から始めて $$v \gets v^\ast$$ と更新することを繰り返した。
ビームサーチとは、これを状態集合 $$\mathbf{v} = \{ v_0 \} \subseteq V$$ から始めて $$\mathbf{v} \gets \mathbf{v}^\ast$$ と更新するものである。
ただし $$\mathbf{v}^\ast$$ は集合 $$\bigcup _ {v \in \mathbf{v}} N(v)$$ の中から $$g(v)$$ の小さい順に $$k$$ 個取り出してできる集合と定義する。

#### ビームサーチは貪欲法の拡張である

これは明らかである。
特に、状態を状態の集合へ拡張したものと理解できる。

#### chokudaiサーチについて

([chokudaiサーチ(ビームサーチ亜種)の利点の話 - chokudaiのブログ](http://chokudai.hatenablog.com/entry/2017/04/12/055515)<sup>[archive.org](https://web.archive.org/web/20190306181741/http://chokudai.hatenablog.com/entry/2017/04/12/055515)</sup> が詳しい)

#### 余談: DPとの関連について

([ビームサーチは DP - びったんびったん](http://hakomof.hatenablog.com/entry/2018/12/06/000000)<sup>[archive.org](https://web.archive.org/web/20190306181732/http://hakomof.hatenablog.com/entry/2018/12/06/000000)</sup> が詳しい<sup><a title="ところでこのビームサーチは DP であるという主張から「状態への適切な分割は DP 特有のものではなく、つまり DP の本質はそれではない」のように繋げると面白くなりそう">note</a></sup>)

#### 余談: 不確定性を含む場合に、貪欲法のビームサーチ化は自然に定まらない

(省略)


### 山登り法

#### 非形式的な説明

貪欲法は例えば [山登り法 - Wikipedia](https://ja.wikipedia.org/wiki/%E5%B1%B1%E7%99%BB%E3%82%8A%E6%B3%95)<sup>[archive.org](https://web.archive.org/web/20190306180617/https://ja.wikipedia.org/wiki/%E5%B1%B1%E7%99%BB%E3%82%8A%E6%B3%95)</sup> では次のように説明されている:

>   山登り法とは「現在の解の近傍の内で最も成績の良い解」を近傍解として選び、「現在の解より近傍解の成績の方が良い場合」に近傍解と現在の解を入れ換える局所探索法の方法。

#### 形式化

山登り法は次のようなものであると理解できる。
まず、$$V = X$$ とし無向グラフ $$(V, E)$$ と関数 $$g : V \to \mathbb{R}$$ を適切に選ぶ。
$$v \in V$$ に対し $$N(v) = \{ w \in V \mid (v, w) \in E \}$$ とおき、これは常に非空であるとする。
適切な点 $$v = v_0 \in V$$ から始めて、 $$w \in N(v)$$ をランダムに取り出し $$g(w) \le g(v)$$ ならば $$v \gets w$$ と更新するということを一定回数だけ繰り返し、最終的に得られた $$v \in X$$ が得られた解である。

なお、この $$V$$ を状態空間、その要素 $$v \in V$$ を状態、$$E$$ あるいは $$e \in E$$ を遷移、$$g$$ を評価関数と呼ぶ。
さらに $$N(v)$$ あるいはその要素 $$w \in N(v)$$ を状態 $$v$$ の近傍と呼ぶ。

### 焼きなましとは

#### 非形式的な説明

焼きなましは冶金における焼きなましから名前を取ったアルゴリズムである。
山登り法では解が改善される場合にのみ更新を行うが、悪化される場合でも時間に依存して確率的に更新を行う。

実用の上では次のテクニック集が役に立つ: [hakomo/Simulated-Annealing-Techniques](https://github.com/hakomo/Simulated-Annealing-Techniques)<sup>[archive.org](https://web.archive.org/web/20190306180425/https://github.com/hakomo/Simulated-Annealing-Techniques)</sup>

#### 形式化

山登り法においては $$v \gets w$$ という更新を行うのは $$g(w) \le g(v)$$ の場合のみであった。
焼きなましとは、これを $$g(w) \gt g(v)$$ でも温度 $$t$$ のとき確率 $$p(t, v, w)$$ で更新を行うようにしたものである。

#### 焼きなましは山登り法の拡張である

これは明らかである。
特に、採択確率を非自明なものへと拡張したものと理解できる。

#### 適用条件について

焼きなましや山登り法の適用条件は比較的厳しめで、操作の間の可換性のようなものが要求される。
これは「文脈を持たない」などと表現されることが多い:

-   [北大日立マラソン1stで考えるマラソン入門 - hoshi524のブログ](http://hoshi524.hatenablog.com/entry/2017/12/01/043534)<sup>[archive.org](https://web.archive.org/web/20190307141408/http://hoshi524.hatenablog.com/entry/2017/12/01/043534)</sup>
-   [colunさんのマラソンマッチ関連の話 - Togetter](https://togetter.com/li/876191)<sup>[archive.org](https://web.archive.org/web/20150924072723/https://togetter.com/li/876191)</sup>

#### 多点スタートについて

(省略)

#### 状態プールについて

焼きなましは通常は単一の状態のみを保持するが、複数の状態を保持する派生を考えることもできる。
これを状態をプールする焼きなましと呼ぶ。

#### 余談: 位相の言葉を用いての整理について

(省略)


## 本論

#### 貪欲法と山登り法の類似について

両者は共にグラフ上を単純な形で探索するアルゴリズムである。
形式化された形の両者を観察すれば、差異は主に以下の $$3$$ 点であることが分かる:

-   有向グラフか、無向グラフか
-   近傍をすべて見るか、ランダムに取り出すか
-   状態空間を別に用意するか、解空間をそのまま使うか

しかしこれらの違いは常に見られるものではない。
山登り法を有向グラフ上で行う場合はあるし、貪欲でも近傍を尽くせない場合はランダムにいくつか取り出して対処する場合はある。
山登り法 (や特に焼きなまし) において、解空間をそのまま使うのでなくこれを緩和して状態空間を作る (ただし解に到達できない可能性を孕む) ことは多い。

このように見れば、貪欲法と山登り法との区別は曖昧であることが分かる。
また一方の性質をもう一方へ持ち込むことが有用であることも分かる。

#### 焼きなましとビームサーチの関係について

焼きなましは山登り法の自然な拡張のひとつであり、ビームサーチは貪欲法の自然な拡張のひとつであった。
よって焼きなましとビームサーチの区別も曖昧であることは想像が付く。

実際に (いくらかの乱暴さはあるが) 次のように対応を説明できる:

-   貪欲法やビームサーチの評価関数に乱数を足し込むのは、山登りを焼きなましにする変化と同じことである
-   山登り法や焼きなましで状態を複数保持するのは、貪欲法をビームサーチにする変化と同じことである
-   多点スタートをビームサーチに適用したものが chokudai サーチである
    -   初期解や先頭付近での選択への依存性が大きいときに、これを変えながらアルゴリズムを繰り返し実行する、という意味で類似がある

このように対応を取ることにより、焼きなましとビームサーチとの間で知識を共有することができる。
例えば、焼きなましは時間経過と共に採択確率が減少するが、ビームサーチも序盤は評価関数に大きめの乱数を加え、終盤はこれをほとんど加えずに点数を優先するようにすれば、適切に多様性が確保され点数が向上するのではないか、などと予想を立てることができる<sup><a title="この予想の真偽は未検証なので注意してほしい">note</a></sup>。

#### 貪欲法と山登り法の差異について

貪欲法と山登り法の区別は曖昧であると言った。
しかしまったく同一であるとも思えない。
ではこれらの間の差として最も重要なものは何だろうか？

これは、状態の間のグラフが有向か無向かの違いが本質的であると言える。
候補としては先に挙げた $$3$$ 点である。
近傍をどのように検査するかや、解空間を状態空間として使い回すかどうかは、どちらも単に実装の都合であるように思われるので選びたくはない。
焼きなましを行う際の要件として可換性や可逆性のようなものがあり、またビームサーチを行う要件としてはこれがないことを考えると、状態の関係が有向グラフなのか無向グラフなのかの違いは (しばしば成り立たないとしても) 重要であるように見える。

このような整理によって、概要の節で示した図式が従う。

## 追記

### その他の類似の例

ランダムウォーク、モンテカルロ法、タブーサーチなども、山登り法の部分や拡張と見ることができる。
また、タブーサーチの重複除去という発想はビームサーチのそれと近い。

### この記事への反応

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">chokudaiサーチ＋乱数、っていうのは囲碁のモンテカルロ木探索そのものに見える</p>&mdash; るふぁ (@lpha_z) <a href="https://twitter.com/lpha_z/status/1103409265551634437?ref_src=twsrc%5Etfw">2019年3月6日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">多変数を順番に焼きなまし、は内側が焼きなましで外側が貪欲だと解釈できる？</p>&mdash; るふぁ (@lpha_z) <a href="https://twitter.com/lpha_z/status/1103415362568151041?ref_src=twsrc%5Etfw">2019年3月6日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

拡張アンサンブル法はよく分かっておらず、次のツイートの真偽はまだ判定できていない:

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">また、焼きなまし＋状態空間保持、は拡張アンサンブル法ですね</p>&mdash; るふぁ (@lpha_z) <a href="https://twitter.com/lpha_z/status/1103410871290626050?ref_src=twsrc%5Etfw">2019年3月6日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>


---

# 貪欲法、山登り法、焼きなまし、ビームサーチ、これらの間の関係について

-   2019年  3月  7日 木曜日 23:30:00 JST
    -   [@kosakkun](https://twitter.com/kosakkun) さんに読んでもらい、文章の分かりにくかった点を修正
-   2019年  3月  8日 金曜日 03:00:00 JST
    -   [@lpha_z](https://twitter.com/lpha_z) さんの挙げた類似の例を追記
