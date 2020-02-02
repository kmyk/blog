---
layout: post
alias: "/blog/2016/02/18/anagol-easy-regexp/"
title: "Anarchy Golf 47. easy regexp"
date: 2016-02-18T13:34:57+09:00
tags: [ "writeup", "anarchy-golf", "golf", "perl", "ruby", "regex", "glob", "parsing" ]
---

去年のcode festivalの際にshinhさんにgolfの練習法を聞いたらanagolの過去問を勧められたので、それをやっていこうと思う。

perlで考えていて300byteぐらいのしか書ける気がしなかったので諦めて他人のを読みました。bashやってたら可能だったかもしれないが、perlでこの展開は思い付けない。rubyのそれはglob使ってないのに短くてすごい。

## [easy regexp](http://golf.shinh.org/p.rb?easy+regexp)

### whio氏 81byte perl

``` perl
s!.(\w+)]!(@{[$1=~/./g]})!,y/()| /{},/,s/(B|{[^}]+})\?/{,$1}/g,print<"$_\n">for<>
```

globを上手く使っている。
手元では最後の`\n`を消さないとちゃんと動かなかった。

平たく整形するとこう。

``` perl
$_=<>;
s!.(\w+)]!(@{[$1=~/./g]})!;
y/()| /{},/;
s/(B|{[^}]+})\?/{,$1}/g;
print < "$_\n" >;
```

以下のように変形し、

1.  `(Objective-|Aspect|Concept)?[CD](++|--|#|omega)?`
2.  `(Objective-|Aspect|Concept)?(C D)(++|--|#|omega)?`
3.  `{Objective-,Aspect,Concept}?{C,D}{++,--,#,omega}?`
4.  `{,{Objective-,Aspect,Concept}}{C,D}{,{++,--,#,omega}}`

最後に[`<file*glob>`](http://perldoc.perl.org/perlop.html#Gory-details-of-parsing-quoted-constructs)を使って展開している。


まず`s!.(\w+)]!(@{[$1=~/./g]})!;`は`[]`の処理。`[(\w+)]`とは書けないので`.(\w+)]`と上手く回避し、`$1=~/./g`つまり`split//,$1`として文字に分割し、listにして文字列に埋め込むことで間に空白を挟んでいる。

`y/()| /{},/;`は以下のような挙動を使っている。

``` sh
$ echo abcdef | perl -pe 'y/abcde/ABC/'
ABCCCC
```

`s/(B|{[^}]+})\?/{,$1}/g;`は`?`の処理。テストケースを見て必要なものだけ処理している。

最後の展開におけるglobとはつまり

``` sh
$ bash
$ echo {a,b,c}
a b c
```

ってなるアレ。他にも

``` sh
$ ls
a.pl  a.pl~  tags.lock  test
$ perl -e 'print <"*.pl">'
a.pl
```

とかできる。

### flagitious氏 114byte ruby

``` ruby
def r n,s=''
n[/(\W(.*?)[])]|.)\??/]?(l=$'
r l,s if$&['?']
$+.split($+['|']||'').map{|j|r l,s+j}):puts(s)end
r *$<
```

普通に再帰降下してる。
1.8なrubyでの提出だけど手元の2.3でも動いた。

整形。

``` ruby
def r(n,s='')
    if n[/(\W(.*?)[])]|.)\??/]
        l=$'
        r l,s if $&['?']
        $+.split($+['|']||'').map{|j|r l,s+j}
    else
        puts(s)
    end
end
r *$<
```

rubyの関数定義`def`の括弧は省略できる。

まず`r *$<`は`r(*ARGF)`であり、この場合`r gets`と同じ。

`if n[/(\W(.*?)[])]|.)\??/]`は[String#\[\]](http://docs.ruby-lang.org/ja/2.0.0/method/String/i/=5b=5d.html)。ここにおいては[String#=~](http://docs.ruby-lang.org/ja/2.0.0/method/String/i/=3d=7e.html)で完全に置き換えられる。`?`まで含むひとつの塊の切り出し。

`l=$'`はマッチより後ろの部分を保存。

`r l,s if $&['?']`は`?`により無視された場合の処理。[`$&`](http://docs.ruby-lang.org/ja/2.0.0/method/Kernel/v/=26.html)。

`$+.split($+['|']||'').map{|j|r l,s+j}`が主な再帰。
[`$+`](http://docs.ruby-lang.org/ja/2.0.0/method/Kernel/v/=2b.html)は

>   現在のスコープで最後に成功した正規表現のパターンマッチでマッチした中で最後の括弧に対応する部分文字列

であり、`{}` `()`の内側あるいは単一の文字。これを適当に`|`か` `で切り分け、そのそれぞれに関して再帰している。
