---
category: blog
layout: post
date: "2016-08-03T16:12:25+09:00"
title: "文脈自由文法とその構文解析法"
tags: [ "context-free-grammer", "parsing", "lr", "ll", "slr", "lalr", "glr", "chomsky-normal-form", "greibach-normal-form", "shunting-yard-algorithm", "precedence-climbing-method", "dp", "yacc", "parsec", "antlr", "cyk-algorithm", "earley-parser" ]
---

文脈自由文法とその構文解析法についてのまとめ[^5]。

-   一般に文脈自由文法の構文解析というと$\rm{LR}$等だが、ついでに操車場アルゴリズムのあたりも混ぜた。
-   オートマトンの話はしない。
-   エラー回復みたいな話もしない。
-   字句解析は済ませてあるものとして、tokenの意味で文字と言う。
-   使うmetaな記号として
    -   非終端記号は$A, B, S$
    -   終端記号は$a, b, c$
    -   記号列は$\alpha, \beta, \gamma$
-   主に参考にしたのは <https://www.amazon.co.jp/dp/4798114685> (通称: タイガーブック)。

## 文脈自由言語とは

-   <https://ja.wikipedia.org/wiki/%E6%96%87%E8%84%88%E8%87%AA%E7%94%B1%E8%A8%80%E8%AA%9E>
-   <https://twitter.com/kinaba/status/746339457196953600>
-   <https://twitter.com/kinaba/status/746340883029590016>

文脈自由文法で定義できる言語。
文脈自由文法とは、

-   $X \to \gamma$ ($X$は非終端記号 $\gamma$は記号列)

の形の規則の集合で、つまりBNFを思えばよい。
言語$\\{ \mathrm{a}^n\mathrm{b}^n \mid n \in \mathbb{N} \\}$は属すけど$\\{ \mathrm{a}^n\mathrm{b}^n\mathrm{c}^n \mid n \in \mathbb{N} \\}$は属さない。

## 階層

-   <http://d.hatena.ne.jp/kazu-yamamoto/20081201/1228115457>
-   <http://d.hatena.ne.jp/jetbead/20120930/1349014672>

形式言語の強さとして一般に 正則言語 $\subseteq$ 文脈自由言語 $\subseteq$ 文脈依存言語 $\subseteq$ 帰納的可算言語 という順序がある。
今注目しているのは文脈自由言語と種々あるその構文解析法であるが、これら全ての構文解析法が全ての文脈自由言語を解析できる訳ではないため、構文解析法(の扱える言語の集合)間にもさらに階層がある。
主には以下のような階層になっている。CYK法等は最も大きい。

![階層構造の図](/blog/2016/08/03/context-free-grammar/hierarchy.svg)

-   画像の出典: <http://dragonbook.stanford.edu/lecture-notes/Stanford-CS143/12-Miscellaneous-Parsing.pdf>
-   <https://www.amazon.co.jp/dp/4798114685> にもほぼ同じ図が載ってる

## 操車場アルゴリズム

<https://ja.wikipedia.org/wiki/%E6%93%8D%E8%BB%8A%E5%A0%B4%E3%82%A2%E3%83%AB%E3%82%B4%E3%83%AA%E3%82%BA%E3%83%A0>

中置記法の数式を対象とし後置記法に直すアルゴリズム。各演算子は結合向きの別と優先度を持てる。$O(N)$。

スタックをひとつ持ち、これに演算子を積み込んでいく。
前置記法での表現では(`a + b * c` のように)同じように並んでいても、後置記法であれば優先順位の遅い演算子(`+` など)ほど後ろに現れるため、演算子の出現順序を(`a b c * +` のように)入れ替える必要があるが、これをスタックにいったん遅い演算子を退避させることで実現する。
スタックが優先順位でソートされている(ただし括弧があるとそこで順序はリセットされる)という不変条件を守りながら適当にすれば実装できる。

状態数が主にひとつだけのpushdown automatonになってる[^citation-needed][^1]。

## Precedence climbing method

-   <http://eli.thegreenplace.net/2012/08/02/parsing-expressions-by-precedence-climbing/>
-   <https://en.wikipedia.org/wiki/Operator-precedence_parser#Precedence_climbing_method>

中置記法の数式を対象とした手法。
聞き慣れない名前ではあるが、中身は良く見る感じのやつ。暗にスタックを使っているが(目的が同じなので必然的に)操車場と同じことをしている。$O(N)$。
$i$番目の文字から始まる優先順位が$p$以上の範囲を解析する、という関数で再帰。

例えば `a + b + c * d * e ^ f * g + h` を考えて、全体の目標は$0$番目の文字から始まる優先順位が`+`以上の範囲。
この範囲は`a` `b` (`c`から始まる優先順位が`*`以上の範囲) `h`と分けられる。
さらに再帰して、`c` `d` (`e`から始まる優先順位が`^`以上の範囲) `g`となる。

演算子の先読みが少し必要だが、素直に実装すればよい。

## 括弧を用いた方法

<https://en.wikipedia.org/wiki/Operator-precedence_parser#Alternative_methods>

中置記法の数式を対象とした、英wikipediaに載ってた名前の分からない暴力的な方法。でも$O(N)$。

演算子の周りにその優先順位に対応した数の括弧を足すことで、木構造を作る。

例えば `a + b * c - (d + e)` に対し、

-   先頭 $\to$ `(((`
-   `+` (優先順位 $1$) $\to$ `))+((` (括弧 $2$)
-   `*` (優先順位 $2$) $\to$ `)*(` (括弧 $1$)
-   `(` (優先順位 $0$) $\to$ `(((` (括弧 $3$)
-   `-` $\to$ `))-((`
-   `)` $\to$ `)))`
-   末尾 $\to$ `)))`

と置換して、 `((( a ))+(( b )*( c ))-(( ((( d ))+(( e ))) )))`を作る。
優先順位の大きい演算子から順に小さい数の括弧を割り当てている。

括弧が付いてしまえば木構造ができているので、優先順位のことを忘れてしまえる。
結合順のあたりは未処理なので適当にする。

雑にごまかしたいときに使えばよいっぽい。
`y/()/[]/`とかして適当に`eval`に投げつけたりするとよさげ。
sed向き？

## LL法

左からなめて最左導出。再帰下降型構文解析。先読みの数が高々$k$なら$\rm{LL}(k)$で上限なしなら$\rm{LL}(\ast)$。

## LL(0)

-   <http://stackoverflow.com/questions/5253816/are-there-such-a-thing-as-ll0-parsers>
-   <http://stackoverflow.com/questions/21328816/from-article-on-wikipedia-is-this-a-ll0-grammar>

先読みができない。不安になるぐらい貧弱。

先読みができないというのは、現在の状態(非終端記号)のみから(入力によらず)使用する規則を決めないといけないということ。
その制約から、

-   各非終端記号はちょうどひとつの置き換え規則のみを持つ
-   もちろん再帰とか選言とかKleene starとかそういうのは禁止

なので全部inlineに展開できて、単一の規則で表せるはず。

## LL(1)

-   <https://www.amazon.co.jp/dp/4798114685>
-   <http://www.prefield.com/algorithm/string/parser.html>

再帰下降型構文解析。$O(N)$。
何も知らずに書こうとしたらたぶん自然とこれに近いものになる。
$1$文字だけ先読み、つまり現在の状態と未処理の$1$文字から使用する規則を決める。

使用する規則の表、あるいは、非終端記号と終端記号の積を左辺として選言を持たないような文法規則 $f : N \times \Sigma \to {}^{\lt \omega}(N \cup \Sigma)$ を構成し、これに従い決定的に遷移しながら入力をなめる。
表から手で書くと、非終端記号の数だけ関数を用意して相互再帰になることが多い。
なお$\rm{LL}(k)$なら$f : N \times {}^k\Sigma \to {}^{\lt \omega}(N \cup \Sigma)$になる。

この表の構成が肝。統一的に求める方法がある。

入力は入力末尾記号$\\$$を持つものとする[^2]。以下を再帰なりで適当に作る。

-   $\operatorname{nullable}(A) \in 2$: 非終端記号$A$が$\epsilon$を導きうるか
-   $\operatorname{first}(\gamma) \subseteq \Sigma$: 記号列$\gamma$から導かれる文字列の左端になりうる終端記号
-   $\operatorname{follow}(A) \subseteq \Sigma$: 非終端記号$A$の後ろに続きうる終端記号

これらより、$\operatorname{director}$集合を定める。

-   $\operatorname{director}(A, \gamma) \subseteq \Sigma$ ($A$は非終端記号 $\gamma$は記号列で規則$A \to \gamma$が存在)
    -   $a \in \operatorname{director}(A, \gamma) \Leftrightarrow a \in \operatorname{first}(\gamma) \lor (\operatorname{nullable}(A) \land a \in \operatorname{follow}(A))$
    -   $a \in \operatorname{director}(A, \gamma)$は、状態が$A$のときに先読み$a$が来たなら$\gamma$に遷移すべき、を表す

これから表$f(A, a) = \gamma \Leftrightarrow a \in \operatorname{director}(A, \gamma)$とすれば、遷移表ができる。
この表に衝突がある、つまり$f$が(部分)関数にならなかったとき、対象とした言語は$\rm{LL}(1)$の範囲外の言語だったということになる。

ただし表の衝突を最低限の部分で防ぐため、事前に以下が行われる。

1.  左再帰の除去
    -   中間非終端記号を追加し、左再帰としての出現をそれ以外の規則でinline展開すればよい
    -   $A \to A B$と$A \to C$を、$A \to C A'$と$A' \to B \mid \epsilon$に。複数の場合も適当にする
2.  左括り出し
    -   中間非終端記号を追加し、common prefixになっている部分を空にする
    -   $A \to B a$と$A \to B b$を、 $A \to B A'$と$A' \to a \mid b$に

## LR法

-   <https://www.amazon.co.jp/dp/4798114685>

左からなめて最右導出。bottomupな構文解析、区間DPぽいやつ。
$\rm{LL}(k)$だと左から$k$文字まで見た時点で使用する規則決定を迫られ、これが困難なので、決定を延期する。特に、決定対象の右端とさらに$k$文字まで見てから決定するようにする。
$k$個先読みなら$\rm{LR}(k)$だが$k \ge 2$はほぼ使われないらしい。

変種がいくらかあるが、変種でないものはcanonical LRとも呼ぶ。このcanonicalは正準。

## LR(0)

-   <https://www.amazon.co.jp/dp/4798114685>

先読みはないが、右端導出そのものがある種の先読みなのでそこまで弱くはない。

文法は開始記号$S$を持つものとし[^2]、入力は終端記号$\\$$を持つものとする。

各規則の右辺に区切り記号$\cdot$を付けたものを$\rm{LR}(0)$項(termではなくitem)と呼ぶ。
例えば規則$E \to E + F$に対しては以下の$4$個が項。

-   $E \to \cdot E + F$
-   $E \to E \cdot + F$
-   $E \to E + \cdot F$
-   $E \to E + F \cdot$

解析器の状態は項の集合で、次に適用されうるものを集めたものとなる。$\cdot$はどこまで見たかを表す。
項の集合$X$に関し、関数$f(A \to \alpha \cdot B \beta) = (B \to \cdot \gamma)$に閉じた閉包を考え、これが状態になる。
右端導出であるため葉側から導出するので、状態に$A \to \alpha \cdot B \beta$があるなら先に$B \to \cdot \gamma$が適用されうるからである。

状態間の遷移を考える。
状態$X$のとき終端記号$a$が来たときを考えると、$\cdot$が$a$を越えてひとつ右に移動した項の集まりが次の状態である。
つまり状態$X' = \\{ (A \to \alpha a \cdot \beta) \mid (A \to \alpha \cdot a \beta) \in X \\}$。
非終端記号に関しても同様にして、それが来たときの次の状態を定める。

状態を頂点とし終端記号/非終端記号を辺とする有効グラフが作れる。
開始記号の唯一の規則から導かれる項$S \to \cdot A \\$$を開始状態として、特にその連結成分だけを作る。
このグラフは特にcanonical $\rm{LR}(0)$ collection(正準$\rm{LR}(0)$集成)と呼ばれる[^3]。

構文解析の実行は、このグラフの上をスタック(と入力)と共に走ることで行われる。
スタックには状態(項の集合あるいはその番号)とその状態に遷移するために使った終端/非終端記号の対が積まれる。
開始状態と適当な記号のみをスタックに積んだところから始め、以下を繰り返す。
ただしその実行で、実行に複数の選択肢が発生する可能性があるなら言語のエラー。$\rm{LR}(0)$では対応していなかったこととなる。

-   shift: 入力から$1$文字取ってきて対応する辺で遷移し、遷移先状態と使った辺をpush
    -   shift対象が非終端記号ならgotoと呼ぶ
-   reduce: 現在の状態に$A \to \gamma \cdot$という形があれば、stackから$\gamma$に対応する分の記号をpopして入力に$A$をunpop
    -   reduce対象が$S \to A \\$$ならacceptと呼ぶ
    -   つまり辺を逆に辿っている

無事に入力末尾$\\$$を読んで遷移できたら解析成功。途中で止まれば失敗。

このグラフの上を走る操作は、事前に$\rm{LR}$構文解析表という形にまとめられるのが普通。
言語のエラーは表の同じマスに複数の規則が書かれているかという形で判断される。

## SLR(1)

-   <https://www.amazon.co.jp/dp/4798114685>

Simple LR。$\rm{LR}(0)$よりちょっとましなやつ。

ほとんど全ては$\rm{LR}(0)$と同じ。
差異は、shift/reduce衝突やreduce/reduce衝突が起こったとき。
そのとき$1$文字先読みして、reduce先の非終端記号の$\operatorname{follow}$集合に先読みした文字が入っていないとき、そのようなreduceをしない。
これは明らかに失敗を導く遷移を刈る操作である。

必然的に先読みを伴うので、$\rm{SLR}(0)$というのは存在しない[^citation-needed]。

## LR(1)

-   <https://www.amazon.co.jp/dp/4798114685>

先読み数$k = 1$である。このため項の形が$\rm{LR}(0)$のそれと異なり、表がけっこう大きくなる。

$\rm{LR}(1)$項は、$\rm{LR}(0)$項のそれに加え先読み記号を持つ。
つまり$(A \to \alpha \cdot \beta, a)$の形をしている。
閉包を作るときの関係は$(A \to \alpha \cdot B \beta, a) R (B \to \cdot \gamma, b) \text{ for all } b \in \operatorname{first}(\beta a)$となる。

遷移の方法は単に$\cdot$をずらすだけであるなど、その他諸々に変化はないが、先読み部分により要素が区別されるため結果は違うものとなる。

## LALR(1)

-   <https://www.amazon.co.jp/dp/4798114685>

Look-Ahead LRの略[^4]。yaccで使われているもの。

$\rm{LR}(1)$の表を作って、これから先読み部分だけが違う頂点を併合してしまう。
これは表の大きさを減らすためであり、表現力のためではない。
もちろん衝突は発生しうるが、あまり問題にならないらしい。

## 表の修正

-   <https://www.amazon.co.jp/dp/4798114685>

衝突が起こるなら表を手で修正しちゃえばいいじゃない、というやばげな解決方法がある。
これは言語の曖昧性を決め打ちにより解決することに対応する。当然推奨されない。

## GLR

-   <https://en.wikipedia.org/wiki/GLR_parser>
-   <http://qiita.com/jonigata/items/69381937b2d5b0af410c>

衝突が起こるなら全部試せばいいじゃない、という安直な方法。幅優先探索をする。
扱えるのはさすがに文脈自由言語の全体で、最悪$O(N^3)$ではあるが、決定的な文法なら分岐が発生せず$O(N)$なのでそれなり。

曖昧な文法を扱えるので結果となる構文木も複数となり、全て求めると森になる。このため永続木のようなものが必要になるらしい。

基にする表はどの$\rm{LR}$のものでもよさそうだが[^citation-needed]、$\rm{LALR}(1)$のものが効率的らしい。

## Chomsky標準形

-   <https://en.wikipedia.org/wiki/Chomsky_normal_form>
-   <http://stackoverflow.com/questions/30533855/does-chomsky-normal-form-have-left-recursion>

以下の形:

-   $A \to BC$ ($A,B,C$は非終端記号)
-   $A \to a$ ($A$は非終端記号 $a$は終端記号)
-   $S \to \epsilon$ ($S$は開始記号)

空になる非終端記号が基本的にない、構文木が二分木になる、というのが嬉しい。左再帰や右再帰は存在しうる。

要求から外れる規則を、規則中にinlineに展開することで吸収させれば作れる。
適切にやれば元の$O(k^2)$の規則数に収まる。
以下を順にやればよくてそれぞれそう難しくないが、適用順序は重要。

-   START: 開始記号$S$を追加
-   TERM: $A \to a$以外の形で現れる終端記号$a$を$N_a \to a$な非終端記号$N_a$を導入して除去
-   BIN: $A \to X Y \dots Z$の形の規則を中間非終端記号を追加して除去
-   DEL: $\epsilon$規則をinline展開して除去
-   UNIT: $A \to B$の形の規則を$B$をinline展開して除去

## CYK法

<https://en.wikipedia.org/wiki/CYK_algorithm>

Cocke-Younger-Kasami法。Chomsky標準形にして$O(N^3)$の区間DP。
$\mathrm{dp} : N \times N \times \Sigma \to 2$ ($N$は入力長 $\Sigma$は非終端記号の集合)の形で、Chomsky標準形の性質を使って、特に工夫なく$O(N^3K)$ ($K$は規則の数)でやる。
このようなDPするparserはchart parserという。

## Earley法

<https://ja.wikipedia.org/wiki/%E3%82%A2%E3%83%BC%E3%83%AA%E3%83%BC%E6%B3%95>

CYK法と同様のchart parserだがtopdownで、$\rm{LR}(0)$項を使う。
$O(N^3)$ではあるが文法に曖昧性がなければ$O(N^2)$になる。
LR法をDPにした感じ。

集合値の動的計画法で、入力位置から$\rm{LR}(0)$項と開始位置への関数$S : N \to \mathcal{P}(\rm{Item} \times N)$を以下による漸化式で作成する。
漸化式とはいっても再帰的なので、各$k$に関して左から右へ、それぞれで可能な限り繰り返すことになるだろう。

-   予測: $S(k) \gets S(k) \cup \\{ (Y \to \cdot \gamma, k) \mid (X \to \alpha \cdot \beta, j) \\}$
    -   閉包を取るのに相当する[^citation-needed]。
-   走査: 入力の$k$文字目$a_k$を使って、$S(k+1) \gets S(k+1) \cup \\{ (X \to \alpha a_k \cdot \beta, j) \mid (X \to \alpha \cdot a \beta, j) \in S(k) \\}$
    -   shiftに相当する[^citation-needed]。
-   完了: $S(k) \gets S(k) \cup \\{ (Y \to \alpha X \cdot \beta, i) \mid (X \to \gamma \cdot, j) \in S(k), (Y \to \alpha \cdot X \beta, i) \in S(j)\\}$
    -   reduceに相当する[^citation-needed]。

## Greibach標準形

<https://en.wikipedia.org/wiki/Greibach_normal_form>

以下の形:

-   $A \to a \vec{X}$ ($A$は非終端記号 $a$は終端記号 $\vec{X}$は非終端記号列)
-   $S \to \epsilon$ ($S$は開始記号)

どんな文脈自由文法でもこの形に直せるのだが、規則は最悪で元の$O(k^4)$に膨れる。
しかし解析は$O(N)$になる[^citation-needed]。

予言的に構文解析できるので、stack系のesolangで継続を積みながらやる感じだとこれを使うのが楽。

## tools

### yacc

-   <https://en.wikipedia.org/wiki/Yacc>
-   <https://www.gnu.org/software/bison/manual/bison.html>

伝統的な$\rm{LALR}(1)$の構文解析器。preprocessor的に動いてCを吐く。同様な字句解析器であるlexと併せて使われる。
抽象構文木を作るのが重たい処理だった時代からあるようで、そのあたりは自分でしないといけない。

手元ではbisonへのwrapperとして存在していた。
軽い用途に使うにはCだとつらいのでpythonのplyあたりがよさげ。

-   <https://pypi.python.org/pypi/ply>

### Parsec

-   <https://hackage.haskell.org/package/parsec>
-   <https://wiki.haskell.org/Parsec>

Haskellの有名なparser combinators library。
文脈依存言語まで対応してるけど$\rm{LL}(1)$文法のときが最も効率的だそうな。
字句解析まで適当にできるしmonadicに書けるしでとても便利。

他にも似たものはあるので、使うときはそれらも検討すべき。

-   <https://hackage.haskell.org/package/trifecta>
-   <http://hackage.haskell.org/package/attoparsec>

### ANTLR

-   <http://www.antlr.org/>
-   <https://ja.wikipedia.org/wiki/LL%E6%B3%95#LL.28k.29_.E6.A7.8B.E6.96.87.E8.A7.A3.E6.9E.90.E5.99.A8.E7.94.9F.E6.88.90.E3.83.84.E3.83.BC.E3.83.AB>

$\rm{LL}(\ast)$を使うつよいやつ。
字句解析や抽象構文木まで組み立ててくれる。
$k \ge 2$な$\rm{LL}(k)$に関する状況を変えるものだったらしい。

使ったことはないです。

---

## 付録: 参考実装

$\rm{LL}(1)$や$\rm{LR}(0)$の実装までするつもりでしたが、やればできそうだったこともあり途中で飽きました。
頭から始めて肝心なところの直前で力尽きるのほんとだめですね。

### 操車場アルゴリズム

``` python
#!/usr/bin/env python3
functions = [ 'f', 'g' ]
operators = {
    '!': (5, 'R'),
    '^': (4, 'R'),
    '*': (3, 'L'),
    '/': (3, 'L'),
    '+': (2, 'L'),
    '-': (2, 'L'),
    }
prec  = lambda s: operators[s][0]
assoc = lambda s: operators[s][1]

def ordered(a, b):
    if a not in operators or b not in operators: # '(' or functions
        return True
    return prec(a) < prec(b) \
            or (assoc(b) == 'R' and prec(a) == prec(b))

def parse(tokens):
    result = []
    wye = []
    for t in tokens:
        if t == '(':
            wye += [t]
        elif t == ',' or t == ')':
            while wye[-1] != '(':
                result += [wye.pop()]
            assert wye[-1] == '(' # or input error
            if t == ')':
                wye.pop()
            if wye and wye[-1] in functions:
                result += [wye.pop()]
        elif t in operators:
            while wye and not ordered(wye[-1], t):
                result += [wye.pop()]
            wye += [t]
        elif t in functions:
            wye += [t]
        else:
            assert t.isdigit()
            result += [t]
        # invariant
        for u, v in zip(wye, wye[1:]):
            assert ordered(u, v)
    while wye:
        assert wye[-1] != '(' # or input error
        result += [wye.pop()]
    return result

assert parse('1 + 2 + 3 * 4 + 5'.split()) == '1 2 + 3 4 * + 5 +'.split()
assert parse('1 - 2 - 3'.split()) == '1 2 - 3 -'.split()
assert parse('1 ^ 2 ^ 3'.split()) == '1 2 3 ^ ^'.split()
assert parse('1 + 2 * ( 3 + 4 * 5 ) * 6 + 7 * 8 + 9'.split()) == '1 2 3 4 5 * + * 6 * + 7 8 * + 9 +'.split()
assert parse('f ( 1 , 2 ) * g ( 3 + 4 * 5 , 6 + 7 , 8 - 9 )'.split()) == '1 2 f 3 4 5 * + 6 7 + 8 9 - g *'.split()

# unary operators
assert parse('1 ! 2'.split()) == '1 2 !'.split()
assert parse('! ! ! 1 + ! ! 2 * ! 3'.split()) == '1 ! ! ! 2 ! ! 3 ! * +'.split()
assert parse('- 1'.split()) == '1 -'.split()
assert parse('- 1 * 2 - 3'.split()) == '1 2 * - 3 -'.split()
```

## Precedence climbing method

``` python
#!/usr/bin/env python3
operators = {
    '^': (4, 'R'),
    '*': (3, 'L'),
    '/': (3, 'L'),
    '+': (2, 'L'),
    '-': (2, 'L'),
    }
prec  = lambda s: operators[s][0]
assoc = lambda s: operators[s][1]

def parse(tokens):
    def atom(i):
        if tokens[i] == '(':
            x, i = init(i+1)
            assert tokens[i] == ')'
            return x, i+1
        else:
            return int(tokens[i]), i+1
    def expr(i, lhs, min_prec):
        lhs = lhs
        while i < len(tokens) and tokens[i] in operators and prec(tokens[i]) >= min_prec:
            op, i = tokens[i], i+1
            min_prec = prec(op)
            rhs, i = atom(i)
            next_prec = prec(op) + (1 if assoc(op) == 'L' else 0)
            rhs, i = expr(i, rhs, next_prec)
            lhs = ( lhs, op, rhs )
        return lhs, i
    def init(i):
        lhs, i = atom(i)
        return expr(i, lhs, 0)
    result, i = init(0)
    assert i == len(tokens)
    return result

assert parse('1 + 2 + 3 * 4 + 5'.split()) == (((1, '+', 2), '+', (3, '*', 4)), '+', 5)
assert parse('1 - 2 - 3'.split()) == ((1, '-', 2), '-', 3)
assert parse('1 ^ 2 ^ 3'.split()) == (1, '^', (2, '^', 3))
assert parse('1 + 2 * ( 3 + 4 * 5 ) * 6 + 7 * 8 + 9'.split()) == (((1, '+', ((2, '*', (3, '+', (4, '*', 5))), '*', 6)), '+', (7, '*', 8)), '+', 9)
```


[^citation-needed]: 要出典
[^1]: 単項演算子の動きがちょっと不安
[^2]: 開始記号は必要？ なぜ？
[^3]: 要出典。あってるとは思うけど
[^4]: いまいちどうLook-Aheadなのか分からない。むしろnot Look-Aheadぽさがある
[^5]: 変なところがあったらぜひ教えてください。
