---
layout: post
redirect_from:
  - /writeup/golf/anarchy-golf/bracket-matching/
  - /blog/2016/02/22/anagol-bracket-matching/
date: 2016-02-22T05:22:57+09:00
tags: [ "writeup", "golf", "anarchy-golf", "ruby", "perl", "sed", "regex", "greedy" ]
---

# Anarchy golf 51. Bracket Matching

最短の解答の1.5倍以内には入っているので、今回はそこそこ戦えたかなあという印象。

## [Bracket Matching](http://golf.shinh.org/p.rb?Bracket+Matching)

### 拙作 perl 119byte

``` perl
$e='[])}>]';for(<>){chop;s/.$e// while/.($e)/&chr(2-(')'eq$1)+ord$&)eq$1;print$_?'failed at: '.(/$e/?$&.$':EOL):yes,$/}
```

今回初めて知った`-l`を使ったところ111byteに縮んだ。

``` perl
#!perl -pl
$e='[])}>]';s/.$e// while/.($e)/&chr(2-(')'eq$1)+ord$&)eq$1;$_=$_?'failed at: '.(/$e/?$&.$':EOL):yes
```

### shinh氏 ruby1 93byte

``` ruby
#!ruby -pl
$_=/.([]})>](.+)?)/&&7>$1[0]^$&[0]?$2?$`+$2:'yes':"failed at: #{$1||:EOL}"until/e/
```

テストケース多めで嘘は付けないなあと思っていたが、それでも平然と嘘を複数個仕込んでくるのすごい。

#### 解読

``` ruby
#!/usr/bin/ruby -pl
until /e/
    $_ = (/.([]})>](.+)?)/ && (7 > ($1[0] ^ $&[0]))) ?
        ($2 ?
            $` + $2 :
            'yes') :
        "failed at: #{$1 || :EOL}"
end
```

``` ruby
#!/usr/bin/ruby -pl
```

1行目。shebang。`-l`はnewlineを上手くやるoption。

>   Enables automatic line-ending processing, which means to firstly set $\ to the value of $/, and secondly chops every line read using chop!.

``` ruby
until /e/
```

2行目。`$_`に`yes`あるいは`failed at: `が入るまでのloop。

``` ruby
    $_ = (/.([]})>](.+)?)/ && (7 > ($1[0] ^ $&[0]))) ?
```

3行目。captureと判定。

`/.([]})>](.+)?)/`でもっとも左の閉じ括弧を中心にcaptureし、`7 > ($1[0] ^ $&[0]))`で閉じ括弧`$1[0]`とその左の括弧`$&[0]`の種類が同じかどうかを判定。

以下のような対応より、排他的論理和をとって下位3bit以外が一致していれば種類は同じとなる。よって比較は`7`でなくて`8`でもよい。
基本的に最も左の括弧をcaptureするので、種類が同じであることの判定だけで十分である。
ただし`))`のような入力に`yes`を返す。

| `(` | `0b0101000` |
| `)` | `0b0101001` |
| `[` | `0b1011011` |
| `]` | `0b1011101` |
| `{` | `0b1111011` |
| `}` | `0b1111101` |
| `<` | `0b0111100` |
| `>` | `0b0111110` |


``` ruby
        ($2 ?
            $` + $2 :
            'yes') :
```

4,5,6行目。balancedな括弧の対があったとき。
その対より後ろになにもなければ`yes`。

``$```には対の手前、`$2`には対の後ろが入っている。
三項条件演算子の条件部`$2`に関して、`(()`のような入力と`()(`のような入力には共に`failed at: EOL`を返すべきだが、これは前者に`yes`を返す。しかし前者のような入力が存在しないため、`$2`のみを判定すればよい。

### irori氏 sed 84byte

``` sed
:
s/^\([[({<]*\)\(()\|\[]\|{}\|<>\)/\1/
t
/^$/cyes
s/[[({<]*/failed at: /
s/ $/ EOL/
```

sedには以前から興味があったが、遂に手をだす時がきたっぽい。
やはり好きな感じの言語だった。

#### sed 参考文献

-   [sed ってなんなの？, 2006-10-10 - 兼雑記](http://shinh.hatenablog.com/entries/2006/10/10)
    -   [sed カテゴリーの記事一覧 - 兼雑記](http://shinh.hatenablog.com/archive/category/sed)
-   [code golf - Tips for golfing in sed - Programming Puzzles & Code Golf Stack Exchange](http://codegolf.stackexchange.com/questions/51323/tips-for-golfing-in-sed)
-   <https://www.gnu.org/software/sed/manual/sed.html>
-   [Sed - An Introduction and Tutorial](http://www.grymoire.com/Unix/Sed.html)

#### 解読

``` sed
:
s/^\([[({<]*\)\(()\|\[]\|{}\|<>\)/\1/
t
```

1,2,3行目。

消去可能な対が存在しかつ最も左側である間、それを消し続けるloop。

`/^$/cyes`

3行目。

整形すると`/^$/ c yes`。行を`yes`で置換。

### shinh氏 perl 85byte

``` perl
#!perl -pl
$_=/.([]})>])/&&$+^$&^'3'|0?$`.$'||yes:"failed at: $+".($+?$':EOL)until/e/
```

#### 解読

``` perl
#!/usr/bin/perl -pl
until (/e/) {
    $_ = /.([]})>])/ && ($+ ^ $& ^ '3' | 0)
        ? ($` . $') || yes
        : "failed at: $+" . ($+ ? $' : EOL)
}
```

``` perl
    $_ = /.([]})>])/ && ($+ ^ $& ^ '3' | 0)
```

3行目。

`$+`は

>   The text matched by the last bracket of the last successful search pattern.

であり、この行の`$+`は`$1`と同じ。今回の`| 0`は`int`と考えてよい。`'3'`は`'0'`とかでも動く。

### ySas氏 perl 82byte

``` perl
#!perl -pl
$_=3x/.([]})>])/^$+^$&|0?$`.$'||yes:"failed at: $+".($+?$':EOL)until/e/
```

#### 解読

整形。

``` perl
#!/usr/bin/perl -pl
until (/e/) {
    $_ = (3 x /.([]})>])/) ^ $+ ^ $& | 0
        ? $` . $' || yes
        : "failed at: $+" . ($+ ? $' : EOL)
}
```

変更点は3行目の

``` perl
    $_ = (3 x /.([]})>])/) ^ $+ ^ $& | 0
```

`x`演算子は左辺を文字列として右辺回繰り返したものを作るが、これにより`/.../ ? '3' : ''`を実現している。
