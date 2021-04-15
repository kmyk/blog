---
layout: post
redirect_from:
  - /writeup/golf/anarchy-golf/split-into-multiples-of-7/
  - /blog/2016/03/17/anagol-split-into-multiples-of-7/
date: 2016-03-17T17:53:04+09:00
tags: [ "writeup", "golf", "anarchy-golf", "ruby", "perl", "brainfuck", "sed", "regex" ]
---

# Anarchy Golf 944. Split into multiples of 7

## [Split into multiples of 7](http://golf.shinh.org/p.rb?Split+into+multiples+of+7)

### ruby 2系 42byte

``` ruby
$<.chars{|c|$><<c<<$/[$.=($.*3+c.to_i)%7]}
```

``` ruby
s='';$<.chars{|c|$><<c<<$/[(s+=c).to_i%7]}
```

1位に8byte差。
`/\B/`からの <code> $` </code> 、何故気付けなかったのだろうという感じがある。

#### angel氏/mitchs氏/olf氏/ludo氏 34byte

``` ruby
$><<gets.gsub(/\B/){$/[$`.to_i%7]}
```

みんな一緒。`gsub(/\B/)`と`$/[...]`に気付けばこれになる。
ruby 1系の提出はこれの`$/[...]`を`$/if...<1`で置き換えたもの。

### perl 42byte

``` perl
$_=<>;print$&,$/x!(($n.=$&)%=7)while s/.//
```

`for<>=~/./g`を使えば1位に並ぶ。

``` perl
print$_,$/x!(($n.=$_)%=7)for<>=~/./g
```

#### llhuii氏/teebee氏/tails氏/angel氏 36byte

``` perl
print$_,$/x!(($n.=$_)%=7)for<>=~/./g
```

あるいは

``` perl
print$_,$/x!($n="$n$_"%7)for<>=~/./g
```

皆ほぼ同一。

### brainfuck 75byte

``` brainfuck
,+[-
    .
    [>+<-]> add
    + incr
    >+++++++< 7
    [->-[>+>]>[+[<+>-]>>]<<<<] mod
    >>[<[-]>>+++<-] mult 3 and flag
    <[+++.>]> 3 newline
,+]
```

divmodは<http://esolangs.org>から借りてきたそのまま。

#### mitchs氏 55byte

``` brainfuck
,+[-.<[>---<-]>+[>[<[->]<]+++++++<]>+++>>[>]<<[.>]>>,+]
```

定数除算や分岐が上手い。

##### 解読

``` brainfuck
,+[-
    .
    <[>---<-]> mult minus 3
    + incr
    [> mod
        [<[->]<]
        +++++++ 7
    <]
    >+++ 3 newline
    >>[>]<< if the reminder exists then shift
    [.>]
    >>
,+]
```

``` brainfuck
,+[-
    ...
,+]
```

まず最外のloop。
`EOF`($-1$)まで読む。newlineは$3 \pmod 7$なので無視してよい。

``` brainfuck
    .
    <[>---<-]> mult minus 3
    + incr
```

読んだ文字を即出力する。読んだ文字のascii code $a$と、ひとつ左に置いてある前回のloopの結果$b$から、$a + 1 - 3b$を作る。$+1$は`ord('0') % 7 #=> 6`であるため。
$-3$倍なのは次の$b' = 7 - (a + 1 - 3b)$であるから。

``` brainfuck
    [> mod
        [<[->]<]
        +++++++ 7
    <]
```

7で剰余を取る。`0 0 [n] 0`から、$n = 0 \pmod 7$なら`0 0 [0] 7`、そうでないなら`[0] 7 0 7-n%7`。

``` brainfuck
>+++ 3 newline
```

先ほど控えておいた$7$から$10$を作る。

``` brainfuck
>>[>]<< if the reminder exists then shift
[.>]
```

`[10] 0 n`から$n$の真偽に応じて右に、ひとつずれる。
まだずれておらず$10$の上に居るなら、出力してひとつずれる。


#### angel氏 63byte

``` brainfuck
,+[-.<[->---<]>+[>[-]<<+++++++[->-[>++>]<<<]>]>[>]>>[--.>]<<,+]
```

##### 解読

``` brainfuck
,+[-
    .
    <[->---<]> mult minus 3
    + incr
    [> mod
        [-]
        <<+++++++ 7
        [->-[>++>]<<<]
    >]
    >[>]
    >>[--.>]<<
,+]
```

``` brainfuck
    [> mod
        [-]
        <<+++++++ 7
        [->-[>++>]<<<]
    >]
```

剰余。`0 [0] n x`から`[0] n%7 0 12-2n`を作る。
他はだいたい同じ。

### sed

難しいと判断して見送ったが、やってみてもよかったかもしれない。

#### mitchs氏/tails氏

``` sed
s/./&876543210\n/g
s/\(.\).*\1/\1/mg
s/\B./-/g
:
s/-\n*\(\w\)/\1---/
s/-\{7\}//
t
```

5,6行目の順序を除いて同一。
嘘を付いている。

##### 解読

``` sed
s/./&876543210\n/g
s/\(.\).*\1/\1/mg
s/\B./-/g
```

各文字に関して、その後ろに`876543210\n`を追加し、その文字から次のその文字に一致するところまで削除し、それ以降の文字を`-`で置換。

例えば`145537`と入れると以下のようになる。

```
1-
4----
5-----
5-----
3---
7-------
```

``` sed
:
s/-\n*\(\w\)/\1---/
s/-\{7\}//
t
```

`char -* - newline* char`を`char -* char ---`で置き換える。つまり`-`の数を$10$倍して下の位に降ろしている。
そして`-------`をひとつ消去。適当な位置から$7$を引いている。これを交互にやる。

嘘がある。例えば入力が`7714`だとすると、

```
7-------
7-------
1-
4----
```

から

```
7------
7---
1-
4----
```

となり、最終的に$1$行目は`77`になる。
