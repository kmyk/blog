---
layout: post
alias: "/blog/2016/03/31/anagol-left-pad/"
date: 2016-03-31T19:34:24+09:00
tags: [ "golf", "writeup", "anarchy-golf", "ruby", "sed", "brainfuck", "c", "perl" ]
"target_url": [ "http://golf.shinh.org/p.rb?left+pad" ]
---

# Anarchy Golf 946. left pad

[時](https://medium.com/@azerbike/i-ve-just-liberated-my-modules-9045c06be67c#.fmuoxzddt)[事](http://cpplover.blogspot.jp/2016/03/npmkik.html)[ネ](http://yosuke-furukawa.hatenablog.com/entry/2016/03/27/152500)[タ](http://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm)。

数の処理の場合、sedはbrainfuckより難しいように思った。

## ruby 41byte

<http://golf.shinh.org/reveal.rb?left+pad/kimiyuki_1458833086>

``` ruby
#!ruby -pl
~/ \d+ /;$_=$'.rjust$&.to_i,$`
```

暫定最短解。
`/ \d+ /`か`/ \d+./`かの違いを除き全てこれ。
1,2系ともに同一。
mitchsさん、xsotさん、olfさん、Histocratさんと私が提出。

`~/ \d+ /`で`$_`を3分割し、そのままな処理をしてくれる関数に投げる。

## perl 38byte

<http://golf.shinh.org/reveal.rb?left+pad/kimiyuki_1458880680>

``` perl
print$`x(/ \d+ /+$&-length$').$' for<>
```

暫定最短解。
加算の順序等の違いを除き同一。
tailsさん、teebeeさん、llhuiiさんと私が提出。

`rjust`のようなものはないので、普通に実装する。`/ \d+ /`が`1`であることを使う。

## c

そろそろcもやろうかなと思った。
ozyさんの[蟹本](https://book.mynavi.jp/ec/products/detail/id=24465)は買って積んであるし読まねば。

### 私 91byte

<http://golf.shinh.org/reveal.rb?left+pad/kimiyuki_1459320135>

``` c
main(c,d,s){for(;~scanf("%c%d%*c",&c,&d);puts(s))for(d-=strlen(gets(s));0<d--;)putchar(c);}
```

``` c
main(c,d,s) {
    for (; ~ scanf("%c%d%*c",&c,&d); puts(s))
        for (d -= strlen(gets(s)); 0 < d -- ;)
            putchar(c);
}
```

`s`は`char **env`であるが、これを文字列用の領域として使用している。それ以外は特に変なことはしていない。

### xsotさん 84byte

<http://golf.shinh.org/reveal.rb?left+pad/xsot_1459225714>

``` c
d;main(c,s){while(~scanf("%c%d%c",&c,&d))puts(memset(s-d,c,d-=strnlen(gets(s),d)));}
```

``` c
d;
main(c,s) {
    while (~ scanf("%c%d%c",&c,&d))
        puts( memset(s-d, c, d -= strnlen( gets(s), d)));
}
```

`strlen`でなく`strnlen`を使い`d >= 0`を保証し、その上で`s`の手前を`memset`し、そのまま出てきた第1引数を`puts`。

anagolでは引数が右から評価されるらしい。
一般には、実引数の評価順序は規定されていない。

### llhuiiさん 86byte

<http://golf.shinh.org/reveal.rb?left+pad/llhuii_1459127983>

``` c
c;main(i,s){for(;i-->strlen(s)?putchar(c):gets(s-scanf("%c%d",&c,&i)/2,c&&puts(s)););}
```

lphaさんの86byteもだいたい同じ。

``` c
c;
main(i,s) {
    for (; i -- > strlen(s)
            ? putchar(c)
            : gets( s - scanf("%c%d",&c,&i) / 2, c && puts(s)); )
        ;
}
```

staticな変数`c`の初期値は$0$であるので、初回の実行では`c && puts(s)`により`puts(s)`は短絡により実行されない。
成功時のscanfの返り値が$2$となることを使い、`gets(s-1)`とすることにより、余分な空白を除去している。

## sed

`\x01` `\x02` `\04` `\x09`(tab文字)は見やすさのため`^A` `^B` `^D` `^I`に置換してある。
文字列先頭の`^`と紛らわしいが、これは一切使われていない。

### 私 216byte

<http://golf.shinh.org/reveal.rb?left+pad/kimiyuki_1459271849>

縮まず。プロらに$2$倍差つけられた。

``` sed
h
s/. //
s/ .*//
s/./;&9876543210/g
s/;\(.\)[^;]*\1/;/g
t
:
s/\([^;]*\);/\1\1\1\1\1\1\1\1\1\1/
t
G
s/\n\(.\).*/\^A\1/
t1
:1 s/\(.\)^A\(.\)/^A\2\2/
t1
s/..//
G
s/\n. [^ ]* /^A^B/
t2
:2
s/.\(^A.*\)^B\(.\)/\1\2^B/
t2
s/^A\|^B//g
```

### tailsさん 113byte

<http://golf.shinh.org/reveal.rb?left+pad/tails_1459181117>

だいたい何やってるかは分かるけど、同じようなの思い付けと言われるとまだ厳しい。

``` sed
:
s/^A/^B9876543210&9^B/
s/\(.\)^B.*\1\(^A*.\).*^B/\2/
t
s/.*^I./&^I/
/^I$/s/./&&/
s/ \w\+/&^A^I/
/ 0*^A/!b
s/. \w*^A^I* \|^I//g
```

``` sed
s/ \w\+/&^A^I/
```

まず実行されるのがこの行。幅の数字列の後ろに`^A^I`を付与。

``` sed
/ 0*^A/  ! b
```

その次の行では、数字列がなんらかの$0$を表すものでなければ、先頭へ。

``` sed
s/^A/^B9876543210^A9^B/
s/\(.\)^B.*\1\(^A*.\).*^B/\2/
```

数字列の末尾に`^A`があるのでこれを置換し、
最下位の数字に対応する位置まで削り、削った次の文字だけ残す。
つまりdecrement。なので繰り下がりも処理する。それが`0`であった場合は、そこを`^A9`にした上でもう一度。

``` sed
s/.*^I./&^I/
```

`.*`は最も末尾の`^I.`を選択するために存在する。そのようなものの次の文字の後ろに`^I`を加える。
`Ixxxxx`から始めて、`IxIxxxx` `IxIxIxxx` `IxIxIxIxx` `IxIxIxIxIxI` `IxIxIxIxIxI`と続き、終わる。
出力幅から文字列長を引いている。

``` sed
/^I$/  s/./&&/
```

もし末尾に`^I`があるなら、先頭の一文字を複製。
余った出力幅分、文字を複製している。

``` sed
s/. \w*^A^I* \|^I//g
```

まだ数字が残っていればもう一度。
そうでなければこの行で不要な文字を消去し終わる。


### %20さん 115byte

<http://golf.shinh.org/reveal.rb?left+pad/%2520_1459311591>

``` sed
:
s/^I/^A10^I987654321^B/
s/\(.\)^A.*\1\(^I*.\).*^B/\2/
t
s/ \S\+/&^I/
/^I ^D/s/./&&/
/^I ^D/!s/.^D\|$/^D&/
T
s/. 0*^I //
T
s/^D//g
```

``` sed
s/ \S\+/&^I/
```

最初の実行はこの行。
幅の数字列の後ろに`^I`。

``` sed
/^I ^D/ ! s/.^D\|$/^D&/
```

次にこの行の選言の右により、文字列末尾に`^D`。

``` sed
T
s/. 0*	 //
T
```

この最後の`T`を踏んで冒頭へ。

``` sed
s/^I/^A10^I987654321^B/
s/\(.\)^A.*\1\(^I*.\).*^B/\2/
```

はdecrement。tailsさんのと同じ。captureした文字まで読んでその次の文字だけ残す。

``` sed
s/ \S\+/&^I/
```

再度、幅の数字列の後ろに`^I`。

``` sed
/^I ^D/s/./&&/
/^I ^D/!s/.^D\|$/^D&/
```

`^D`を手前にずらし、`^I `までずらし終われば先頭を複製。

### mitchsさん (+ tailsさん, %20さん) 110byte

<http://golf.shinh.org/reveal.rb?left+pad/mitchs+%28tails%2C%2520%29_1459425072>

終了後の提出。

``` sed
:
s/^A/^B9876543210&9^B/
s/\(.\)^B.*\1\(^A*.\).*^B/\2/
t
s/.*^I./&^I/
/^I$/s/./&&/
s/ \w\+/&^A^I/
T
s/. 0*^A^I* //
T
s/^I//g
```

前半はtailsさんのものそのまま、後半`T`からは主に%20さんのものが強くまざっている。

## brainfuck

### 私 179byte

<http://golf.shinh.org/reveal.rb?left+pad/kimiyuki_1459327248>

``` brainfuck
,+[->>,>,<[>-->+<<--]>[>[<-<+>>-]<<<[>>++++++++++<<-]>>[<<+>>-],<[>-->+<<-]>]>--
----<+[->>,<[>->+<<-]>]+>+[<[+<<]>>[>>]<-]<--[<+[<<+>>-]<]<<+>[-<-[>>>]<<]<[<.>-
]>>[>>>]>>[.>>]>,+]
```

``` brainfuck
,+[-
    @c
    >>,>, space and first digit
    c 0 32 @d
    <[>-->+<<--]>[
        c n 0 @d 16
        >[<-<+>>-]<
        <<[>>++++++++++<<-]>>
        [<<+>>-]
    ,<[>-->+<<-]>]
    c n 0 @0 16
    >------<+[-
        >>,<[>->+<<-]>
    ]
    c n 0 0 0 s 0 s 0 s * 0 s 0 @0 10
    +>+[
        <[+<<]
        >>[>>]<-
    ]
    <--
    c n 0 0 0 s 0 s 0 s * 0 s 0 @10
    [
        <+[<<+>>-]<
    ]
    c n l @0 0 s 0 s 0 s * 0 s 0 10
    <<+>[
        -<-[>>>]<<
    ]
      @0 c 0  l 0 0 s 0 s 0 s * 0 s 0 10
    or   c n @0 0 0 s 0 s 0 s * 0 s 0 10
    <[<.>-]
    >>[>>>]
    >>[.>>]>
,+]
```

数文字負番地にはみ出す。

$2$文字目の空白は捨ててよい定数$32$なので、これを使い回す。
まず$2$で割って$16$にし、$2$倍して引いて空白$32$判定、さらに$1$倍を引いて、数字$48 \dots 57$を数$0 \dots 9$に。
$6$引いて改行$10$にし、これで改行判定しながら読み、読み終わったら引いた分を足し戻す。
最後は文字列の末尾に置いておいて出力に使う。

### mitchsさん 124byte

<http://golf.shinh.org/reveal.rb?left+pad/mitchs_1458831504>

``` brainfuck
,+[->,>,<[>-<-]>[<[>++++++++++<-]>[<+>-],>++++++++[<----<-->>-]<]-[[<]<[->]>>[>]
<+>,----------]+[<]<[<.>-]>>[+++++++++.>],+]
```

簡潔でかつ短くてすごい。

``` brainfuck
,+[-
    >,>,
    c 32 @d
    <[>-<-]>
    c 0 @d
    [
        c n @d
        <[>++++++++++<-]>
        [<+>-]
        ,
        >++++++++[<----<-->>-]<   A
    ]
    c n @0
    -[
        [<]<[->]>>[>]   B
        <+>
    ,----------]
    c n 0 s s s @0
    +
    [<]<[<.>-]
    >>[+++++++++.>]
,+]
```

2文字目の空白は3文字目にぶつけて消費し、

``` brainfuck
        >++++++++[<----<-->>-]<   A
```

で、$16$引くのと$32$を引くのを同時にやっている。

``` brainfuck
        [<]<[->]>>[>]   B
```

では読み込みと同時に出力幅をdecrementしている。
