---
category: blog
layout: post
title: "CODE FESTIVAL 2015 短縮王 感想と解説"
date: 2015-11-17T14:38:10+09:00
edited: 2018-10-21T04:38:10+09:00
tags: [ "competitive", "codefestival", "atcoder", "golf", "perl", "ruby", "regex" ]
---

CODE FESTIVAL 2015のコンテンツとして行われたgolf、ショートコーディングコンテスト「短縮王」に関して。
全言語部門の全問題で1位or1位タイを取って総合1位を取りました。
感想と私の提出コードの解説の記事です。

<!-- more -->

## 全体の感想とか

全言語部門で1位を取りました。
賞品はラクリートというロボット掃除機を1つと、ロボット掃除機を模した机の上を落ちないように走り回るおもちゃが3つでした。
golfという正直あまり役に立たない遊びのわりに賞品が豪華で驚きです。<small><del>中の人的に幾何ゲーが元の選択なのだろうが、しかし掃除という選択はなにかの皮肉にしか見えない。普段のコードは綺麗ですよ。</del></small>

c言語部門に関してはさっぱり。c言語のgolfに関する[本](http://www.amazon.co.jp/dp/4839925232)があって、皆これを読んでいたらしい。私は同じ土俵に上がることすらできていなかったようです。
上手くeaxを0にする技や、領域の確保を嫌がって入力をstack上にぶち込む技が必要な争いだったらしい。

一方、全言語部門に関しては、perlとrubyを両方ある程度使えてgolfをやる気がある人が私だけ、という状況。例えばD問題をperlで出しているのは私だけ。
優勝争いには実質ひとりしか参加してなかったように感じました。
c言語部門は白熱してたように見えて羨しかったです。
でも唯一C問題は、あるrubyistと抜いたり抜かれたりを楽しみました。

そういう私も、perl/rubyによるgolfをまともにやったのは今回が初めてです。
`perl golf tips`とかで[ぐぐった](https://www.google.co.jp/search?q=perl+golf+tips)結果を見ながらgolfしていました。
なのでshinhさんの解説でも、知らない知識がかなりたくさん出てきていました。
「golfの入門に良いサイトや本はありますか？」とshinhさんに質問したところ、anarchy golfの過去問の解答を読むこと、c言語に関しては[本](http://www.amazon.co.jp/dp/4839925232)があるということ、を教えていただきました。
とりあえず今は今回の問題のanarchy golf上での出題が期限切れして解答が公開されるのを楽しみにしています。

とにかくgolfはとても楽しかったです。
<small><del>そして後から自分のtwitterを見かえしたら、ほとんどgolfの話題しか呟いてなくてちょっと気持ち悪かったです。</del></small>
参加者少ないのでgolfが初めての人間でも優勝が狙えます。
楽しい上に優勝が狙えるなら参加するしかないですよね。
なので皆さん来年は是非とも全言語部門にも参加してほしいと思います。

## ルール

-   atcoder上で実行される
    -   return codeが非零ならruntime errorに
    -   改行は2byte
    -   使える言語は実用言語ばかり
-   全言語部門と、c/c++部門のふたつが存在
    -   clangは禁止
-   嘘解法も許される (通るなら)
-   問題は[事前公開](http://recruit-jinji.jp/code_fes2015/short.html)されている
    -   ただし入力形式の大幅な変更がある。当日の調整は必須
-   [順位表](http://kenkoooo.com/code_fes2015/)


## [A - もし解けなかったら木の下に埋めて貰っても構わないよ](https://code-festival-2015-shortcoding.contest.atcoder.jp/tasks/cf_2015_shortcoding_a) (anarchy golf: [Code Festival A If you cannot solve this](http://golf.shinh.org/p.rb?Code+Festival+A+If+you+cannot+solve+this)) {#a}

50byte perl

``` perl
$a=(2*<>-1)*<>;$a-=$_ for<>;print$a>0?Pass:Fail,$/
```

激戦区。同じ50byteを提出していた人が他に3人いる。提出時間の差で2位。

### 解説

式変形

-   $s_1 \le \frac{\Sigma_{i=1}^N s_i}{2N}$
-   $2Ns_1 \le \Sigma_{i=1}^N s_i$
-   $(2N-1)s_1 \le \Sigma_{i=2}^N s_i$
-   $(2N-1)s_1 - \Sigma_{i=2}^N s_i \le 0$

``` perl
$a=(2*<>-1)*<>;  # a = (2N-1)s_1
$a-=$_ for<>;  # a -= s_i (2 <= i <= N)
print$a>0?Pass:Fail,$/  # 出力
```

-   `<>`はつまり`getline`
-   perlでは文字列から数値への暗黙変換がある
-   `for(<>){...}`で`STDIN.each{...}`
    -   `$_`に行の文字列が改行付きで入る
-   後置`for`は得
    -   `for(...){...}`が`...for...;`になって4byte前後減る
-   関数呼び出しの`()`は基本的に省略可能
-   perlの識別子は適当に文字列として解釈される (bareword)
    -   `"Pass"`が`Pass`になって2byte減る
    -   `use strict;` pragmaでこの機能を殺せる
-   `$/`には改行文字`"\n"`が入ってるので2byte有利

### 改善

shinhさんの解説を聞いて

-   `join('+', <>)`して`eval`すれば`$a = 0; $a += $_ for <>;`相当のことができる

とのことなので縮めたのが以下。スライドに載ってたのはもうちょっと短かったような気がする。

46byte

``` perl
print~-(<>*2)*<>>eval(join'+',<>)?Pass:Fail,$/
```

golf場では入力が1行に与えられるので`eval s/ /+/g`ってしてたけど、複数行でもできるのは知らなかった。
`~-x`で`x-1`、`-~x`で`x+1`は知ってた。

## [B - Union Find](https://code-festival-2015-shortcoding.contest.atcoder.jp/tasks/cf_2015_shortcoding_b) (anarchy golf: [Code Festival B Union Find](http://golf.shinh.org/p.rb?Code+Festival+B+Union+Find)) {#b}

114byte perl

``` perl
<>;sub r{$j=$t[my$i=pop];$j?$t[$i]=r($j):$i}s/ \d+//,$p=(r$&)-(r$'),$`&&print($p?NO:YES,$/)||$p&&($t[r$&]=$')for<>
```

golf場と入出力形式が同じ。
shinhさんがの管理者権限を使ってgolf場でのやばいperlのコードを紹介してた。まったく読めなかった。

### 解説

``` perl
# union find treeを表す変数は @t
<>;  # 1行目は読み飛ばし
sub r {
    $j = $t[my $i=pop];  # 引数のひとつめをlocal変数$iに積み、その親も取得しglobal変数$jに格納
    $j ? $t[$i] = r($j)  # 親が居るなら再帰して更新
       : $i  # 居ないなら自身が代表元
}
s/ \d+//,  # 入力 "A B C\n" の "B" にだけmatchさせることで、 $` = A; $& = B; $' = C を実現
    $p = (r$&) - (r$'),  # BとCの親が異なるかどうか
    $` && print($p ? NO : YES, $/)  # Aが1なら出力
       || $p && ($t[r$&] = $')  # Aが0なら更新 ただし同じ集合に属するなら無視
    for<>
```

## [C - 割り算と足し算](https://code-festival-2015-shortcoding.contest.atcoder.jp/tasks/cf_2015_shortcoding_c) (anarchy golf: [Code Festival C Div and Add](http://golf.shinh.org/p.rb?Code+Festival+C+Div+and+Add)) {#c}

79byte ruby

``` ruby
def f(i)i-i/10*9+(i>99?9:(1..i-1).map{|j|i%j<1?f(j):0}.max||0)end;p f gets.to_i
```

`(a..b)`, `.upto`, `.times`, `.step`の辺りでずっと試行錯誤していた。`(...)`は知らなかった。

### 解説

$$ f(i) = ({\rm sum~of~digits~of~i}) + \max \{ f(j) \mid 1 \le j \lt i, j \shortmid i \} $$ という再帰関数。dpしてもよいが、再帰の方が短くなった。

``` ruby
def f(i)
    i-i/10*9  # i/10+i%10 に等しい 2桁目以上と1桁目の和
        + ( i>99
                 ? 9  # 100の場合は別処理 差分を足す
                 : (1..i-1).map{ |j|
                       i%j < 1
                               ? f(j)
                               : 0
                   }.max || 0  # maxを取る 空列のときnilになるので対処
          )
end;
p f gets.to_i
```

### 改善

shinhさんの解説で、覚えている範囲で改善

75byte ruby

``` ruby
f=->i{i-i/10*9+(i>99?9:(1..i-1).map{|j|i%j<1?f[j]:0}.max||0)};p f[eval *$<]
```

shinhさん曰く、

-   rubyにはarrow記法による$\lambda$式も存在する
    -   昔はなかった気がする
    -   `-> (args) { body }`
    -   `.call`や`[]`で呼びだす
-   `gets.to_i`より`eval *$<`の方が1byte短い

``` ruby
irb(main):001:0> ->x{x*x}[3]
=> 9
```

<blockquote class="twitter-tweet" lang="en"><p lang="ja" dir="ltr"><a href="https://twitter.com/a3VtYQo">@a3VtYQo</a> lambdaのarrow記法は1.9からです。あと、「.()」は.callと同じになるよう文法で決まっているのですが、これも1.9からです。尤もlambdaの場合は[]メソッドが定義されているので気にしなくて良いのですが。</p>&mdash; しえる(046) (@cielavenir) <a href="https://twitter.com/cielavenir/status/666571230829375489">November 17, 2015</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

教えてもらいました。1.9ということは`?d`で整数`100`を表現して1byte得するテクと共存できない。


### 指摘

<blockquote class="twitter-tweet" lang="en"><p lang="ja" dir="ltr">短縮王Cの最短だったコード（<a href="https://t.co/vJkoCuIBl2">https://t.co/vJkoCuIBl2</a>）に自明な無駄があったので、1文字削った。<a href="https://t.co/EgApZMsdvp">https://t.co/EgApZMsdvp</a></p>&mdash; %20｜残り21928日 (@henkoudekimasu) <a href="https://twitter.com/henkoudekimasu/status/666192669467525120">November 16, 2015</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

74byte ruby

``` ruby
f=->i{i-i/10*9+(i>99?9:(1...i).map{|j|i%j<1?f[j]:0}.max||0)};p f[eval *$<]
```

こういう指摘はとてもありがたいです。

`(...)`はまったく知りませんでした。自明どころか驚きの事実です。精進します。

71byte ruby

## [D - 数列圧縮](https://code-festival-2015-shortcoding.contest.atcoder.jp/tasks/cf_2015_shortcoding_d) (anarchy golf: [Code Festival D Compress numbers](http://golf.shinh.org/p.rb?Code+Festival+D+Compress+numbers)) {#d}

78byte perl

``` perl
$a=<>;@b=split//,<>;pop@b;$a=~s/./($b[0]-=$&)%10||shift@b/eg;print@b?NO:YES,$/
```

perlでの提出者が私だけなので当然1位。なんだか悲しい。

### 解説

Aの数字を先頭から貪欲に足し合わせていって、Bの数字の文字と一致すればふたつを除去する。これを繰り返して、Bが空になり、かつその時Aの数字の総和が0になればよい。

``` perl
$a = <>;  # 1行目は文字列
@b = split//,<>;  # 2行目は文字の配列
pop @b;  # 改行文字をpop
$a =~ s/./
        ($b[0] -= $&) % 10 || shift @b  # $a内の各文字を$&に入れて、$bの先頭から引く。 それが零なら$bの先頭を削除
    /eg;
print@b?NO:YES,$/
```

-   正規表現の`e`modifierは右辺を式として`eval`する。
    -   二重にやる`ee`modifierもある。いくらでもnestさせられるぽい。

shinhさんの解説では`$a`の側でも`s///eg`を使っていたはず。そう長くは映されていなかったので読めず。

### 指摘

<blockquote class="twitter-tweet" lang="en"><p lang="ja" dir="ltr">短縮王Dの最短だったコード（<a href="https://t.co/WcdGTOlnZr">https://t.co/WcdGTOlnZr</a>）に自明な無駄があったので、4文字削った。<a href="https://t.co/y2lQvZqlYp">https://t.co/y2lQvZqlYp</a></p>&mdash; %20｜残り21928日 (@henkoudekimasu) <a href="https://twitter.com/henkoudekimasu/status/666190542598901761">November 16, 2015</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

74byte perl

``` perl
$_=<>;@b=split//,<>;pop@b;s/./($b[0]-=$&)%10||shift@b/eg;print@b?NO:YES,$/
```

これは気付くべきだった。


---

-   Tue Nov 17 20:18:29 JST 2015
    -   rubyのarrow記法に関して教えてもらったので追記
    -   Dの最後で引用してるコードが間違ってたので修正
-   2018年 10月 22日 月曜日 04:43:48 JST
    -   beta版へのlinkになっていたが404していたので旧版に戻す
