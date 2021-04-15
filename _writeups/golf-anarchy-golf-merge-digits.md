---
layout: post
redirect_from:
  - /writeup/golf/anarchy-golf/merge-digits/
  - /blog/2016/04/29/anagol-merge-digits/
date: 2016-04-29T18:33:48+09:00
tags: [ "golf", "writeup", "anagol", "anarchy-golf", "c", "sed", "perl", "ruby", "brainfuck" ]
---

# Anarchy Golf 945. Merge Digits

今回はまったくだめ

## ruby 2系

55byte

<http://golf.shinh.org/reveal.rb?Merge+Digits/kimiyuki_1460757307>

``` ruby
$<.map{|l|a=l.split;$><<$&while a.max.sub! /./,'';puts}
```

### Histocratさん 36byte

<http://golf.shinh.org/reveal.rb?Merge+Digits/Histocrat_1460689180>

``` ruby
#!ruby -pa
gsub(/./){$F.max.slice!0}
```

-   `split`の代わりに、`-a` option[^1]
-   先頭からの破壊的なpopに、`String#slice!`[^2]
-   ちょうど必要回数のloopと出力をするのに、`Kernel.#gsub`[^3]

## perl

76byte

<http://golf.shinh.org/reveal.rb?Merge+Digits/kimiyuki_1461031695>

``` perl
for(<>){@s=split;while($s[1].0){@s=sort@s;$s[1]=~s/.//;print$&;}print@s,$/;}
```

不要な`;`が複数個ある

### teebeeさん 42byte

<http://golf.shinh.org/reveal.rb?Merge+Digits/teebee_1460744837>

``` perl
#!perl -pa
s/./$&x${\(@F=sort@F)}=~s;;;/ge
```

### llhuiiさん 42byte

<http://golf.shinh.org/reveal.rb?Merge+Digits/llhuii_1460767529>

``` perl
#!perl -pa
s!.!$&x$F[$F[1]gt"@F"]=~s///!ge
```

#### 解読

>   -   The empty pattern `//`
>       -   If the PATTERN evaluates to the empty string, the last successfully matched regular expression is used instead.

であるので、 `=~s///` はpop[^4]。

両者の相違であるmaxを取る部分であるが、llhuiiさんのものは分かりやすい。
一方でteebeeさんのそれは、まず直接`sort`をする。しかし`(sort@F)[1]`などとするとlvalue的なものにならないので、`\`によって`@F`のreferenceと`${...}`によるdereferenceを挟んだ上で置換を行っている[^5]。

## c

126byte

``` c
char*p,*q,*r,s[99];main(){for(;~scanf("%s%s",p=s,q=s+50);putchar('\n'))for(;*p+*q;putchar(*q++))strcmp(p,q)>0&&(r=p,p=q,q=r);}
```

変数宣言が多すぎて見苦しいが、どうにもならなかった。

### nuさん 90byte

<http://golf.shinh.org/reveal.rb?Merge+Digits/tails_1461832311>

``` c
char*a[];main(){while(*a&&putchar(*a[bcmp(*a,a[1])<0]++?:10)-10||~scanf("%ms%ms",a,a+1));}
```

単一の`while (...);`で綺麗。
同氏のもうひとつの提出は手元で動かなかった。

#### 解読

整形

``` c
char *a[];
main(){
    while (*a
        && putchar(* (a[bcmp(*a, a[1]) < 0] ++) ? : 10) != 10
        || scanf("%ms%ms", a, a+1) != -1
        );
}
```

`char *a[]`は`char *`への(実質的に0要素の[^6])arrayで、その先頭はbss領域の先頭。
なので(他にglobal変数を使っていなければ)十分長い領域として扱える。

`*a`が`(char *)NULL`でないとき、`putchar`が実行される。
`bcmp`[^7]は`memcmp`と考えてよい。第3引数にはゴミが渡される。
`a ? : c`はGNU拡張の省略記法で、`a ? a : c`と副作用を除いて等価。
`putchar`は引数をそのまま返す。

`*a`が`(char *)NULL`あるいは`putchar`が改行を出力したとき、`scanf`が実行される。
`%ms`はGNU拡張[^8]で、いい感じに`malloc`してくれるようだ。

### tailsさん 91byte

<http://golf.shinh.org/reveal.rb?Merge+Digits/tails_1461832311>

``` c
o;main(p,q){for(;o||~scanf("%s%s",p=q+32,q);putchar(o?:10))o=*(0?"":~strcmp(p,q)?p++:q++);}
```

`0?"":`がすごい。

手元ではsegvで動かなかった。

#### 解読

整形

``` c
int o;
main(int p, int q){
    for(; o || scanf("%s%s", p=q+32, q) != -1
            ; putchar(o ? : 10))
        o = *(0 ? "" : strcmp(p,q) != -1 ? p++ : q++);
}
```

`q`は`char **argv`なので、これを領域として使っている。

``` c
        o = *(0 ? "" : strcmp(p,q) != -1 ? p++ : q++);
```

の左の条件演算は実行時には意味をなさない。しかしこれがないと型が`int`のままであり、

``` c
        o = *(char *)(strcmp(p,q) != -1 ? p++ : q++);
```

と書くことになる[^9]。`0?"":`の5byteと`(char*)`の7byteでは2byteの有利である。


### tailsさん (+ nuさん) 87byte

<http://golf.shinh.org/reveal.rb?Merge+Digits/tails+%28nu%29_1461906785>

``` c
o;main(p,q){for(;o||~scanf("%ms%s",&p,q);putchar(o?:10))o=*(0?"":bcmp(p,q)>0?p++:q++);}
```

#### 解読

tailsさん本人のものを基本に、`%ms`を使用し、`strcmp`を`bcmp`に変更したもの。

比較:

``` c
<   o;main(p,q){for(;o||~scanf("%s%s",p=q+32,q);putchar(o?:10))o=*(0?"":~strcmp(p,q)?p++:q++);}
>   o;main(p,q){for(;o||~scanf("%ms%s",&p   ,q);putchar(o?:10))o=*(0?"": 0<bcmp(p,q)?p++:q++);}
```

## sed

まともな長さで書ける気がしなかったので見送り。
早くsedが書けるようになりたい。

### tailsさん 108byte

<http://golf.shinh.org/reveal.rb?Merge+Digits/tails_1460734343>

``` sed
s/.*/ &z=9876543210z/
:
/\( .*\)\(.\).*\1\(.\).*=.*\2.*\3/!s/ \(.* \)\(\w\)/ \2\1/
s/ \(.\)/\1 /
s/  z.*//
t
```

この手の正規表現見るたびに、正則性とはなんだったのかという気持ちになる。

#### 解読

``` sed
s/.*/ &z=9876543210z/
```

は前処理。`RESULT FOO BARz=9876543210z`という形に。

``` sed
/\( .*\)\(.\).*\1\(.\).*=.*\2.*\3/    ! s/ \(.* \)\(\w\)/ \2\1/
```

条件節の`\1`にはふたつの列の共通接頭辞が入る。それぞれの共通接頭辞の次の文字`\2`,`\3`が`\2` $\gt$ `\3`かどうかを見ている。`\3`には`z`が入りうる。
matchしなかったとき、ふたつめの文字列の先頭をひとつめの文字列の先頭に移動。これは次で結果の文字列の末尾に移される。
`\w`は`.`でもよい。

``` sed
s/ \(.\)/\1 /
```

は、ひとつめの文字列の先頭を結果の文字列の末尾に移動。

``` sed
s/  z.*//
```

は後処理。

### %20さん 115byte

``` sed
s/.*/\n&@@@0123456789/
:
/\n\(.*\)\(.\).* \1\(.\).*@.*\3.*\2/s/\n\(.\)/\1\n/
t
s/\(\n.* \)\(\w\)/\2\1/
/\n @/!b
P
d
```

`P`や`d`があって珍しいしloopの形も複雑で技巧的だなあという印象。

#### 解読

``` sed
s/.*/\n&@@@0123456789/
```

`RESULT\nFOO BAR@@@0123456789`の形。
`@@@`を`;=;`などとしてもよい。

``` sed
/\n\(.*\)\(.\).* \1\(.\).*@.*\3.*\2/    s/\n\(.\)/\1\n/
```

共通接頭辞を取ってその次の文字で比較。`\3`には`@`が入りうる。
`\3` $\lt `\2`なら、ひとつめの文字列の先頭を結果の文字列に移動。
matchし続ける間繰り返す。

``` sed
s/\(\n.* \)\(\w\)/\2\1/
```

ふたつめの文字列の先頭を結果の文字列に移動。

``` sed
/\n @/!b
```

空になったら終了。

``` sed
P
d
```

`P`は最初の`\n`までを出力[^10]、`d`でpatter spaceを削除し次の行へ。

### mitchsさん (+ tailsさん) 105byte

``` sed
s/.*/ &z=9876543210z/
:
/\( .*\)\(.\).*\1\(.\).*=.*\2.*\3/!s/  z.*\| \(.* \)\(.\)/ \2\1/
s/ ./& /
s/ //
t
```

tailsさんのを基本として改良。

#### 解読

``` sed
/\( .*\)\(.\).*\1\(.\).*=.*\2.*\3/    ! s/  z.*\| \(.* \)\(.\)/ \2\1/
/\( .*\)\(.\).*\1\(.\).*=.*\2.*\3/    ! s/     \| \(.* \)\(.\)/ \2\1/
```

条件部はそのまま。
置換の`\w`が`.`になっているのと、`  z.*`を空白ひとつ` `で置換するようになっている。

``` sed
s/ ./& /
s/ //
```

は、元々は

``` sed
s/ \(.\)/\1 /
```

だったもの。ひとつめの文字列から結果の文字列へ移す処理に、`  z.*`が置き換わってできた空白を消す役割を追加した。


## brainfuck

### mitchsさん 185byte

<http://golf.shinh.org/reveal.rb?Merge+Digits/mitchs_1461888378>

``` brainfuck
->,+[->-[>>>,[>+>+<<-]++++[>>--------<<-]>>]+[-<+]+[,>>>>>]<,[<[<+[-[+[<+<+>>-]>]>>[>->+<<-]>[>]>]<<[<+[<<<<]>[>+<<<<<]>>+>>-]>[-<]<<[<<<<<]->>>>>.[-]+[[<<<<<+>>>>>-]>>>>>]]+[-<+]->],+]
```

I was going to try to write it if he writes this (because I have no confidence to write a short code). But his submittion is too near to the deadline for me to write a code.

#### description

I'll read later.

---

# Anarchy Golf 945. Merge Digits

[^1]: <http://docs.ruby-lang.org/ja/2.3.0/doc/spec=2frubycmd.html>
[^2]: <http://docs.ruby-lang.org/ja/2.3.0/method/String/i/slice=21.html>
[^3]: <http://docs.ruby-lang.org/ja/2.3.0/method/Kernel/m/gsub.html>
[^4]: <http://perldoc.perl.org/perlre.html>
[^5]: <http://perldoc.perl.org/perlref.html>
[^6]: `sizeof`しようとすると`invalid application of ‘sizeof’ to incomplete type ‘char *[]’`
[^7]: <http://linux.die.net/man/3/bcmp>
[^8]: <http://stackoverflow.com/questions/11926883/scanf-dynamic-allocation/16044055>
[^9]: はず。 実際には試せていない。
[^10]: <http://linux.die.net/man/1/sed>
