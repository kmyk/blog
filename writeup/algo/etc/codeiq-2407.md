---
layout: post
alias: "/blog/2015/11/19/codeiq-2407/"
title: "CodeIQ 【コードゴルフ】シンプル・ライフゲーム"
date: 2015-11-19T21:38:39+09:00
tags: [ "golf", "codeiq", "writeup", "ruby" ]
---

CODE FESTIVALでgolfをして、その勢いで参加した。ruby内で6位取れたのでちょっと嬉しい。

<!-- more -->

## [【コードゴルフ】シンプル・ライフゲーム](https://codeiq.jp/challenge/2407)

### 問題

ライフゲームを実行して出力する問題。codeiqなので、テストケースは公開された3つだけ、実行は(brainfuckの処理系がバグってて個人的に恨みのある)企業版ideone。

### 提出コード

161byte ruby

``` ruby
n,h,w=(1..3).map{gets.to_i};a=*$<;n.times{a=(0...h).map{|y|(0...w).map{|x|{3=>?*,4=>a[y][x]}[(-3..5).map{|i|a[(y+i/3)%h][(x+i%3-1)%w]}.count ?*]||?.}*''}};puts a
```

`x`と`y`を取っているのは縮めれるだろうなあと思っていたが、縮められず。

### 解説

整形。かなり常識的なコードである。
近傍9マスを眺めて`*`を数えて連想配列と`||`で更新。

``` ruby
n,h,w=(1..3).map{gets.to_i};
a=*$<;
n.times{
    a=(0...h).map{|y|
        (0...w).map{|x|
            {3=>?*,4=>a[y][x]}[
                    (-3..5).map{|i|a[(y+i/3)%h][(x+i%3-1)%w]
                }.count ?*
            ]||?.
        }*''
    }
};
puts a
```

### 反省とか

simanmanさんの解説を読んでの反省

-   配列を2重にして正方向への超過をごまかす
    -   負のindexは後ろから数えた値を取れるのは知っていた
    -   考えれば思い付ける方法だった
-   連想配列でなく配列で更新
    -   これも気付くべき
-   `Enumerable.count { |item| block }`
    -   知らず
    -   rubyに慣れてたら推測できそう
    -   むしろ何故`Enumerable.count(obj)`は使えたのだろう
-   `n,h,w,*f=*$<;`
    -   これはやってみたが`h`と`w`が頻出する状況のためむしろ長くなった
-   `gsub(/./)`と文字の処理ごとにincrementされる変数
    -   `gsub`に関して、perlで似たようなことしたのに思い付けず

闇の魔法のような技は特にないのだよなあ、という印象。
思い付けるべきだったなあ、と感じるような地味な短縮をきっちり全部やっているように見える。もちろんそのきっちり全部やるというのが難しいのだが。

私はgolfのidiomの知識も足りていないが、発想力といった競技プログラミングと共通するような部分で決定的に負けているようだ。


### links

-   [【コードゴルフ】シンプル・ライフゲーム](https://codeiq.jp/challenge/2407)
    -   問題ページ
-   [【コードゴルフ】シンプル・ライフゲーム　～順位表～ - Cozy Ozy](http://d.hatena.ne.jp/Ozy/20151107)
    -   順位表
-   [【コードゴルフ】シンプル・ライフゲーム 参加日記 - simanmanのブログ](http://simanman.hatenablog.com/entry/2015/11/19/203517)
    -   rubyで1位のsimanmanさんのコードと解説
    -   136byte すごい
-   [Ideone.com - 03mWBB - Online Perl Interpreter & Debugging Tool](https://ideone.com/03mWBB)
    -   perlで1位のtailsさんのコード
    -   読めない
