---
layout: post
alias: "/blog/2016/02/20/anagol-tetris/"
title: "Anarchy Golf 49. Tetris"
date: 2016-02-20T02:24:34+09:00
tags: [ "writeup", "anarchy-golf", "golf", "ruby", "perl", "regex" ]
---

<!-- {% raw %} -->

まったく歯が立たない。

## [Tetris](http://golf.shinh.org/p.rb?Tetris)

### 自分で書いてみたやつ ruby2 195byte

`?#`を`'#'`にすればruby1でも動く。

``` ruby
i,a=3,[*$<]<< s=?#*10+$/
i+=1 while(0..3).all?{|j|a[i+2+j]=~/#{a[j].tr' #','. '}/}
4.times{|j|a[i+=1]=a[i].split('').zip(a[j].split'').map(&:max)*''}
a.delete s
puts [' '*10]*(19-a.size),a[4..-1]
```

### shinh氏 perl 80byte

``` perl
$_.=$*=<>until/
 *
/;$_=$*x($/=/# /*6+/##/*2).$_|<>;print$*x($.-1+s%^#*
%%mg).$_
```

動きはするが、末尾に余分な改行が出るケースがある。

``` perl
$* is no longer supported at ./shinh.pl line 2.
$* is no longer supported at ./shinh.pl line 6.
$* is no longer supported at ./shinh.pl line 8.
```

と言われ、

>   `$*` was a variable that you could use to enable multiline matching. After a deprecation cycle, its magic was removed in Perl v5.10.0.

ということなので、これが原因であろう。

#### 解読

簡単に整形。

``` perl
$_ .= ($* = <>) until /\n *\n/;
$_ = ((($* x ($/ = /# /*6 + /##/*2)) . $_) | <>);
print($* x ($. - 1 + s/^#*\n//mg), $_);
```

``` perl
$_ .= ($* = <>) until /\n *\n/;
```

1行目。空白のみの行に到達するまで読む。空白のみの行を含むそれまでを`$_`に、最後に読んだ行つまり空白のみの行を`$*`に代入。

``` perl
$_ = ((($* x ($/ = /# /*6 + /##/*2)) . $_) | <>);
```

2行目。まとめて落下させる。

まず`$/ = /# /*6 + /##/*2`は、`$_`の中の`# `と`##`を数え、その結果から何行下まで落ちるか(テストケースが分かっていることを用いて)計算。その数だけ空白行を`$_`の先頭に追加し、(`$/`を潰しているので)入力の残りの行全てである`<>`と`|`。`|`は文字列を各文字ごとにascii codeでbit orで、

``` python
>>> chr(0b100000)
' '
>>> chr(0b100011)
'#'
```

であることから、いい感じに空白` `とブロック`#`を重ね合わせてくれる。結果、`$_`にはブロックを落下させた直後の状態が入る。

``` perl
print($* x ($. - 1 + s/^#*\n//mg), $_);
```

3行目。`$_`から`#`のみからなる行を削除し、その返り値である削除された行の数と現在行番号`$.`から求めた数だけ、空白のみの行が代入されている`$*`を出力する。そして`#`のみの行が削除された後の`$_`を出力。

今回の変数一覧。<http://perldoc.perl.org/perlvar.html>より、

-   `$_`
    -   >   The default input and pattern-searching space.
-   `$*`
    -   >   `$*` was a variable that you could use to enable multiline matching.
-   `$/`
    -   >   The input record separator, newline by default.
-   `$.`
    -   >   Current line number for the last filehandle accessed.

### shinh氏 ruby1 81byte

``` ruby
#!ruby -p0
4.times{sub /#(.{#{524/~/#/%?\xca}}) /om,' \1#'}
gsub(/
#+$/){puts" "*10}
```

`\xca`はnon-ascii。古いrubyでないと以下のように言われ動かない。鯖と同じ`1.8.7-p352`を使えば解決する。

``` ruby
shinh.rb:2: invalid multibyte char (US-ASCII)
shinh.rb:2: syntax error, unexpected $end
4.times{sub /#(.{#{524/~/#/%?}}) /om,' \1#'}
```

#### 解読

整形。1byteの文字`\xca`は4byteの文字列`\xca`で置き換えても(`?\xca`なので)実行に影響はない。

``` ruby
#!/usr/bin/ruby -p0
4.times { sub /#(.{#{(524 / (~ /#/)) % ?\xca}}) /om, ' \1#' }
gsub(/\n#+$/) { puts " "*10 }
```

``` ruby
#!/usr/bin/ruby -p0
```

1行目。shebang。`ruby -p0`は`ruby -p -0`で、`-0 [octal]`はmanを見ると、

>   Specifies the input record separator ($/) as an octal number. If no digit is given, the null character is taken as the separator.

つまり`-p0`は、`$_`に入力の全部を入れて実行した後`$_`を出力、ということ。

``` ruby
4.times { sub /#(.{#{(524 / (~ /#/)) % ?\xca}}) /om, ' \1#' }
```

2行目。落下ブロックを1ブロックずつ落下先へ飛ばしていく。

`~ /#/`は[Regexp#~](http://docs.ruby-lang.org/ja/2.2.0/method/Regexp/i/=7e.html)で入力全体の中で最初に現われる`#`のindexを計算。これを$i$として、`524 / i % 202`を計算。ruby1.8なので`?c`は数字。計算結果を$n$として、`sub /(.{n}) /om, ' \1#'`という置換。`#XXX `を` XXX#`に置き換えるのを4回行っている。移動させる距離は入力に依存した魔法の数字であるが、正規表現に[`o`オプション](http://docs.ruby-lang.org/ja/2.2.0/doc/spec=2fliteral.html#regexp)

>   一番最初に正規表現の評価が行われた時に 一度だけ式展開を行う

が付いているので、初回の計算結果が4回続けて使われる。

``` ruby
gsub(/\n#+$/) { puts " "*10 }
```

3行目。揃った行の消去の処理。

`$_`の行で`#`のみのに関して、その数だけ` `のみの行を出力し、空文字列で置換。

### ksk氏 ruby1 86byte

``` ruby
gets$\
eval"sub /#(.{%d}) /m,' \\1#';"%"x\x83A"[~/#//4]*4
gsub(/
#+$/m){puts" "*10}
print
```

`\x83`はnon-ascii。shinh氏のものと同様の問題。

``` ruby
ksk.rb:2: invalid multibyte char (US-ASCII)
ksk.rb:2: syntax error, unexpected tCONSTANT, expecting $end
eval"sub /#(.{%d}) /m,' \\1#';"%"xA"[~/#//4]*4
```

### 解読

``` ruby
gets $\
eval (("sub /#(.{%d}) /m,' \\1#';" % "x\x83A"[(~ /#/) / 4]) * 4)
gsub(/\n#+$/m) { puts " "*10 }
print
```


1行目。[`$\`](http://docs.ruby-lang.org/ja/2.2.0/method/Kernel/v/=5c.html)は出力の区切り文字で、defaultは`nil`。[`gets`](http://docs.ruby-lang.org/ja/2.2.0/method/Kernel/m/gets.html)の第1引数は行区切り文字なので、入力を全て読む。結果は`$_`に入る。

``` ruby
eval (("sub /#(.{%d}) /m,' \\1#';" % "x\x83A"[(~ /#/) / 4]) * 4)
```

2行目。ブロックをひとつずつ移動。

`"sub /#(.{%d}) /m,' \\1#';"`の`%d`に`"x\x83A"[(~ /#/) / 4]`を入れたものを、`* 4`して`eval`つまり$4$回実行。
algorithmはshinh氏のものと同一である。

``` ruby
gsub(/\n#+$/m) { puts " "*10 }
print
```

3,4行目はshinh氏のものと同一である。

<!-- {% endraw %} -->
