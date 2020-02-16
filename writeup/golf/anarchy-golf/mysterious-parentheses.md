---
layout: post
alias: "/blog/2016/05/06/anagol-mysterious-parentheses/"
date: 2016-05-06T15:39:42+09:00
tags: [ "golf", "writeup", "anarchy-golf", "anagol", "sed", "brainfuck" ]
"target_url": [ "http://golf.shinh.org/p.rb?mysterious+parentheses" ]
---

# Anarchy Golf 949. mysterious parentheses

## 概要

問題の変換は以下のようなもの。ただし自然数$0$だけ例外的な挙動。

``` python
#!/usr/bin/env python3
import sys
for line in sys.stdin:
    n = int(line)
    s = bin(n)[2:]
    t = ['(' * len(s)] + [[')', '())'][int(c)] for c in s]
    print(''.join(t))
```

## python 2.x

皆72Bで形もほぼ同じ。

### 私 74byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/kimiyuki_1461259965>

``` python
while 1:
 t=''
 for c in bin(input())[2:]:t='('+t+'()'*int(c)+')'
 print t
```

`bin`は間違いだったらしい。
`bin()`に`[2:]`や`str`から`int`への引き戻しの`int()`は確かに重い。

`def`は`return`を要求するため今回は`lambda`の方が短い。

### mitchsさん、xnorさん 72byte

-   <http://golf.shinh.org/reveal.rb?mysterious+parentheses/mitchs_1461260306>
-   <http://golf.shinh.org/reveal.rb?mysterious+parentheses/xnor_1461382580>

``` python
f=lambda n:'('+(n>1and f(n/2)or'')+n%2*'()'+')'
while 1:print f(input())
```

とても平易で良い。`1and`が目を惹く。

### xsotさん 72byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/xsot_1461381305>

``` python
f=lambda n:0**n*'()'or'('+f(n/2)+n%2%n*'()'+')'
while 1:print f(input())
```

`(0**n * '()') or ('(' + f(n/2) + (n%2%n * '()') + ')')`。
`0**n`は`not n`の結合力の強くかつ短い書き方。

### llhuiiさん 72byte

-   <http://golf.shinh.org/reveal.rb?mysterious+parentheses/llhuii_1462330529>

## perl

### 私 94byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/kimiyuki_1461259238>

``` perl
#!perl -pl
use bigint;$a=$b='';$_<<=1;$a.='(',$b='()'x($_%2).')'.$b while$_>>=1;$_=$a.$b||'()'
```

`bigint`を使ったからといって正規表現を使わない必要はなかったらしい。

### tailsさん 63byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/tails_1461299157>

``` perl
#!perl -p
use bigint;s!\d+!(@{[($&/2||'').'()'x($&%2)]})!&&redo
```

#### 解読

``` perl
#!/usr/bin/perl -p
use bigint;
s!\d+!(@{[ ($&/2 || '') . '()' x ($& % 2) ]})! && redo
```

以下のような挙動。

```
111
(55())
((27())())
(((13())())())
((((6())())())())
(((((3)())())())())
((((((1()))())())())())
(((((((())()))())())())())
```

`@{[ ... ]}`は文字列に式を埋め込むidiom[^1]。`${ ... }`だと式の結果を変数名として解釈してその値を埋め込んでしまう。

### %20さん 63byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/%2520_1461300310>

``` perl
#!perl -p
use bigint;0while s;\d+;(@{[($&/2||'').'()'x($&%2)]})
```

実装の特性を突いていて面白い。
末尾に改行文字等が入ると動かなくなる。

#### 解読

正規表現の中身はtailsさんのそれとまったく同じであるが、外側が違う。
`s///`が`s; ... ; ... `として閉じられていない。`-p` option[^2]は一般に以下のような単純な文字列処理により実現されるとされるが、念のためか`;`が付与され、これが`s///`を閉じるのだろう。

``` perl
LINE:
  while (<>) {
      ...            # your program goes here
  } continue {
      print or die "-p destination: $!\n";
  }
```

## ruby

### 私 63byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/kimiyuki_1461300397>

``` ruby
#!ruby -pl
$_=$_.to_i.to_s(2).gsub(/./){$><<?(;$&==?1?'())':?)}
```

### mitchsさん 54byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/mitchs_1461423741>

``` ruby
#!ruby -pl
$_='%b'%$_
gsub(/./){$><<?(
$&>?0?'())':?)}
```

#### 解読

``` ruby
#!/usr/bin/ruby -pl
$_ = '%b' % $_
gsub(/./) {
    $> << ?(
    $& > ?0 ? '())' : ?)
}
```

`%b`はrubyのformat[^3]独自のもので、$2$進数表記にする。
一般に`%d`等で、以下のようになるので、`.to_i.to_s(2)`等とするより大幅に短い。

>   引数が整数でなければ関数 `Kernel.#Integer` と同じ規則で整数に変換されます。

文字が`0`であるか`1`であるかに文字列間の辞書順比較`>`を使っており、等号`==`で行なうより1byte短い。

## c

### 私 156byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/kimiyuki_1462335269>

``` c
char*s,*t;f(n,c){printf("(");for(t=s;*t>47;n+=(*t=*t++/2+24)-48)c=t[1]+=*t%2*10;n&&f(*t=0);printf(c?"())":")");}main(){for(;~scanf("%ms",&s);puts(""))f(0);}
```

``` c
char *s, *t;
f(n, c) {
  printf("(");
  for (t = s; *t; n += (*t = *t++ / 2 + 24) - 48)
    c = t[1] += *t % 2 * 10;
  n &&f(*t = 0);
  printf(c ? "())" : ")");
}
main() {
  for (; ~scanf("%ms", &s); puts(""))
    f(0);
}
```

### tailsさん 137byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/tails_1462155934>

``` c
s[];f(c,d){char*p=s;for(c=d=!printf("(");*p;c&=1)d|=*p++=c*5+(c=*p)/2+24;d&15&&f();printf("())"+2*!c);}main(){for(;gets(s);puts(""))f();}
```

形が私のそれと似ている。

gccだと動かなかったが、clangだと動いた。
`f`内の`for`のあたりが原因ぽい。

#### 解読

``` c
s[];
f(c, d) {
  char *p = s;
  for (c = d = !printf("("); *p; c &= 1)
    d |= *p++ = c * 5 + (c = *p) / 2 + 24;
  d & 15 && f();
  printf("())" + 2 * !c);
}
main() {
  for (; gets(s); puts(""))
    f();
}
```

関数`f`のlocal変数`c`は繰り下がり。
変数`d`は$0$かどうか。論理和で各桁の総和を取り、asciiの数字が$[0b110000, 0b111010)$であることを使って判定。
`"())" + 2 * !c`で`c ? "())" : ")"`に代えている。

### %20さん 137byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/%2520_1462250973>

``` c
t;char*p,*q;main(f,c){for(q=p;~-f?c--:gets(p=c);p+=*p<49)for(*p*f&&main(0,2),printf("(\0\n\0())"+2*f);*q;f=t)t=3-*q%2,*q++=*q+f%3*5+48>>1;}
```

`\0`は生のnull文字。gccでもclangでもsegvするので困る。

とても技巧的だなあという印象。

#### 解読

``` c
t;
char *p, *q;
main(f, c) {
  for (q = p; ~ - f ? c-- : gets(p = c); p += *p < 49)
    for (*p *f &&main(0, 2), printf("(\0\n\0())" + 2 * f); *q; f = t)
      t = 3 - *q % 2, *q++ = *q + f % 3 * 5 + 48 >> 1;
}
```

``` c
t;
char *p, *q;
main(f, c) {
    q = p;
    while (f != 1 ? c-- : gets(p = c)) {
        if (*p * f) main(0, 2);
        printf("(\0\n\0())" + 2 * f);
        while (*q) {
            t = 3 - *q % 2;
            *q = (*q + f % 3 * 5 + 48) >> 1;
            q++;
            f = t;
        }
        p += *p <= '0';
    }
}
```

main再帰。

引数`f`は状態。
`printf`は`f`が$0,1,2,3$ならそれぞれ`(`,`\n`,`())`,`)`を出力。
$1$は `__libc_start_main` から直接呼ばれた場合のみで、このとき`gets`が呼ばれる。
$0$は再帰の直後のみ。

引数`c`は燃料。
`f`が$1$以外のとき、外側のloopをちょうど2回だけ回す為にある。
ただし`f`が$1$のときは`argv`。

内側のloopに関して、$2$で割る処理。
`f`は繰り下がりの状態になっている。
次の状態`f`の控え`t`は必ず$2,3$のどちらか。

### tailsさん + %20さん、lphaさん 130byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/tails+%28%2520%2Clpha%29_1462499026>

``` c
char*p;main(f,d,c){for(p=&p+4;~-f?c--:gets(p);)for(d%16&&main(0.,2),printf("(\0\n\0())"+2*f);*p;f=3-f%2)d|=*p++=f%3*5+(f=*p)+48>>1;}
```

締め切り後の合作。基本は%20さんのもの。
`main(0.,2)`ってなんなんだという気持ちになる。

`\0`は生のnull文字。やはりgccでもclangでもsegvするので困る。

#### 解読

``` c
char *p;
main(f, d, c) {
  for (p = &p + 4; ~ - f ? c-- : gets(p);)
    for (d % 16 && main(0., 2), printf("(\0\n\0())" + 2 * f); *p;
         f = 3 - f % 2)
      d |= *p++ = f % 3 * 5 + (f = *p) + 48 >> 1;
}
```

``` c
char *p;
main(f, d, c) {
    p = &p + 4;
    while (f != 1 ? c-- : gets(p)) {
        if (d % 16) main(0., 2);
        printf("(\0\n\0())" + 2 * f);
        while (*p) {
            d |= *p = (f % 3 * 5 + (f = *p) + 48) >> 1;
            p++;
            f = 3 - f % 2;
        }
    }
}
```

`p`は領域。静的領域に唯一あるので、その後ろを適当に使う。
`f`,`c`の役割は%20さんのものと同じ。
`d`はtailsさんのものと同じ。

`main(0.,2)`の`0.`は、`0ll`でも動く。64bitの$0$を作りstackに積み、ふたつの32bitの$0$として取り出しているのだろう。

## sed

I am interested to sed, but I don't often write the code.
It seems that I should write it now anyway, even if the code is too long, so I'm going to submit a sed answer, at the next time.

### tailsさん 87byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/tails_1461339315>

``` sed
:
s/[1-9]/&a/g
y/123456789b/012345678a/
t
s/\>/)/
s/\<0*/(/
s/aa/b/g
s/a0/5/g
s/a/()/
t
```

#### 解読

おおまかな動作は、tailsさん/%20さんのperl解法と同じ。
特にその数の表現方法は、各桁の数字を`a`による$1$進数として持つ、`0`(あるいは一時的に`5`)を区切りとした$10$進数。

``` sed
:
s/[1-9]/&a/g
y/123456789b/012345678a/
t
```

では、各数字`n`を$0\underbrace{aaa\dots a}\_{n}$という形に変換。

``` sed
s/\>/)/
s/\<0*/(/
```

数字列を括弧で囲う。
`0*`は`0\?`でもよい。

``` sed
s/aa/b/g
s/a0/5/g
s/a/()/
```

$2$で割る。
例えば$5$である`aaaaa0...`なら、`bba0...`、`bb5...`となり、最終的に`aa0aaaaa...`になる。これは繰り下がりを表現できている。

### %20さん 91byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/%2520_1461316831>

``` sed
:
y/_0123456789/ \t012345678/
s/\w/& /g
t
s/\s\+/(&)/
s/  /_/g
s/ \t/5/g
s/ /()/
/\w/b
s/\t//g
```

`\t`は生のtab文字。これを`A`や`;`にすると動かない。

#### 解読

構成はtailsさんのものと同様。

`a`のかわりに空白` `を、`b`にunderscore `_`を、`0`にtab文字`\t`を使っている。

``` sed
s/\s\+/(&)/
```

あたりが目的なのだろう。

## brainfuck

The difference is 59byte.
His code is too short for me.

### 私 248byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/kimiyuki_1462183190>

``` brainfuck
#!/usr/bin/env bfi
,+[-  until eof
    ----------[  until newline
        ->++++++[<------>-]>>  make 1 based digits
    ,----------]
    >++++++++[>+++++<-]+<
    +<<<
    0 0 0 c 0 0 c 0 0 *c 0 0 1 1 40
    [
        [  divide with 2
            -
            0 *n z 0
            [->>+<<[->+>-]<[<<]>]  divmod 2
            0 *0 z&n/2 n%2
            +
            >[<+>-]
            >[>+++++<-]
            <<
        <<<]
        *0 0 0 c 0 0 c 0 0 c 0 0 d 1 40
        >>>-[+<<<]>>>
        0 0 0 0 0 0 *c 0 0 c 0 0 d 1 40
        [>>>]
        0 0 0 0 0 0 c 0 0 c 0 0 d 1 40 *0
        +[>]+[<]>
        0 0 0 0 0 0 c 0 0 c 0 0 *d 1 40 1 b i n 1
        [[>]<+[<]>-]
        0 0 0 0 0 0 c 0 0 c 0 0 *0 1 40 1 b i n d
        +>>.>-<<< <<<  print (
        0 0 0 0 0 0 c 0 0 *c 0 0 1 1 40 0 b i n d
    ]
    0 0 0 *0 0 0 1 1 40 0 b i n a r y    binary is 2/7
    >>> >>+
    1 1 *41 0 b i n a r y
    [->>[>]>+<<[<]<]
    1 1 *0 0 b i n a r y 0 41
    >>[>]<
    0 b i n a r *y 0 41
    [
        0 b i n a r *y 0 41
        --[>>-.+.<<[-]]>>.[<+>-]<<<  print ()) and )
    ]
    *0 0 41
    >>-[>+<----]>.  newline
,+]
```

The code around input is much likely reducible.
But they won't be shorter, when I tried.

### mitchsさん 189byte

<http://golf.shinh.org/reveal.rb?mysterious+parentheses/mitchs_1461999468>

``` brainfuck
,+[+>++<[>++++++[<------>-]>>,----------]+[-<<<]-[<[-]>[<[++>]<[<+<]>>+[-[<+>->>]<[>>>+<]<]>>>]+<[>+<-]<<<[<<<]>>>-[+<<<]>+++++[>++++++++<-]>.>]>[<<[>+<-]>>-[<.+.->-]<+.->>]<<[>+<----]>.,+]
```

#### 解読

``` brainfuck
#!/usr/bin/env bfi
,+[
    +>++<
    [
        >++++++[<------>-]  36
        >>
    ,----------] until newline
    +[-<<<]
    *0 0 0 c 0 0 c 0 0 c 0 0 0  1 base digits
    -[
        0 0 0 0 x *c 0 0 c 0 0 0 b i n
        <[-]>
        [  devide with 2
            d%2 *c 0 0
            <[++>]
            <[<+<]>>+
            x *c 0 0
            [-[<+>->>]<[>>>+<]<]  divmod 2
            x&c/2 *0 0 c%2
        >>>]
        0 0 c 0 0 c 0 0 c 0 0 d *0 b i n
        +<[>+<-]
        0 0 c 0 0 c 0 0 c 0 0 *0 d&1 b i n
        <<<[<<<]>>>
        0 0 *c 0 0 c 0 0 c 0 0 0 d b i n
        -[+<<<]
        0 0 *0 0 0 c 0 0 c 0 0 0 d b i n
        >+++++[>++++++++<-]  40
        0 0 0 *0 40 c 0 0 c 0 0 0 d b i n
        >.>  print (
        0 0 0 0 40 *c 0 0 c 0 0 0 d b i n
    ]
    40 *0 b i n a r y    binary is 1/2
    >[
        40 0 *b i n a r y
        <<[>+<-]>>-
        0 40 *b\1 i n a r y
        [<.+.->-]<+.->>  print ()) or )
        0 40 0 *i n a r y
    ]
    40 0 *0
    <<[>+<----]>.  newline
,+]
```

``` brainfuck
,+[
    +>++<
    [
        >++++++[<------>-]  36
        >>
    ,----------] until newline
    +[-<<<]

    ...

,+]
```

1-basedな数字列として1行読み、先頭へ移動。
1文字目に関して、newlineの分の$10$等の差異を、$6 \cdot 6$を引くのでなくて$6 \cdot 8$を引くようにして吸収している。
$48 - 10 - 36 = 2$なので追加で$1$を引く必要があるが、次の先頭に戻る際にまとめてやることで少し節約できている。


``` brainfuck
[  devide with 2
    <[++>]
    <[<+<]>>+
    [-[<+>->>]<[>>>+<]<]  divmod 2
>>>]
```

`0 0 *-1 0 0 c 0 0 c 0 0 0`という状態から開始。

``` brainfuck
    <[++>]
    <[<+<]>>+
```

$2$で割った結果が入るひとつ左`x`が(この時点では繰り下がりの真偽値なので$1$)なら、`1 *c`から`4 c+3`、そうでなければ`0 c+1`。
$2$で割った結果`x`を1-basedにするためと、$-1$のときを潰すため、数`c`を2-basedにしている。

``` brainfuck
    [-[<+>->>]<[>>>+<]<]  divmod 2
```

divmod。`x *c 0 0`から`x+c/2 *0 0 c%2`。
`c%2`は次の桁の繰り下がりとなる。

数字列が全体として$1$左にずれるので、最終桁の繰り下がりがそのままbinaryのそれとして空間に積まれる。


``` brainfuck
>[
    <<[>+<-]>>-
    [<.+.->-]<+.->>  print ()) or )
]
<<[>+<----]>.  newline
```

出力は普通な感じ。


### mitchsさん 181byte

``` brainfuck
#!/usr/bin/env bfi
,+[
    +>++<
    [
        >++++++[<------>-]
        >>
    ,----------]
    +[-<<<]
    -[
        <[-]>
        [  devide with 2
!           +
!           [-[<+>->>]<[>>>+++++<]<]   divmod 2
        >>>]
        +<[>+<-]
        <<<[<<<]>>>
        -[+<<<]
        >+++++[>++++++++<-]   40
        >.>
    ]
    >[
        <<[>+<-]>>-
!       [<.+.->[-]]  print ()) or )
        <+.->>
    ]
    <<[>+<----]>.
,+]
```

#### 解読

違いは繰り下がり。
それを$0/1$で持っておいて後で配るのではなく、繰り下がったその場で$5$を足す。
その影響で出力の際に`[-]`が必要になるが、全体では短くなる。

---

# Anarchy Golf 949. mysterious parentheses

[^1]: <http://perl-users.jp/articles/advent-calendar/2008/14.html>
[^2]: <http://perldoc.perl.org/perlrun.html>
[^3]: <http://docs.ruby-lang.org/ja/2.3.0/doc/print_format.html>
