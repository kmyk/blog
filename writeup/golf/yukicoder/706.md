---
redirect_from:
  - /writeup/golf/yukicoder/706/
layout: post
date: 2018-06-30T02:11+09:00
tags: [ "competitive", "writeup", "yukicoder", "golf", "perl" ]
"target-url": [ "https://yukicoder.me/problems/no/706" ]
---

# Yukicoder No.706 多眼生物の調査

## 問題

<span>$S_1, \dots, S_N$</span>の最頻値に含まれる `^` の数を答えよ

## 実装

### bash

私の提出 (57byte):

``` sh
read a;sort|uniq -c|sort -n|awk 'END{print length($2)-2}'
```

tailsさんに48byte (<https://yukicoder.me/submissions/269967>) にまで縮められてしまった。

-   $1$行読み飛ばしは `read a` でなく単に `read` でよい
-   `$2` を取り出すのと `-2` するのを `tr -cd ^` でまとめる

### perl

%20さんのperl (38byte) (<https://yukicoder.me/submissions/270027>):

``` perl
++$a[++$$_][y/^//]for<>;print$#{pop@a}
```

「典型idiom使っただけ」って聞こえてきたけどperl弱者には厳しい。

-   `@a` は配列(のreference)の配列。 出現回数$i$と文字列長$j$に対し`$a[$i][$j]`はそのようであるかの真偽値
-   `$$_` は変数 `$_` のdereference ([perldoc](https://perldoc.perl.org/perlref.html#Using-References))。 文字列に対し次のような挙動をするため辞書のように使える (すごい)

```
$ echo a b c d a b a b c | xargs -n1 | perl -e 'print ++ $$_, $", $_ for<>'
1 a
1 b
1 c
1 d
2 a
2 b
3 a
3 b
2 c
```

-   `y/^//` は `$_` 中の `^` の数を数える
-   `++ $a[ ++ $$_ ][ y/^// ]` は文字列長 `y/^//` のものが `++ $$_` 回出現したことを表すため `1` を代入する。 例として次はsample 1のloop終了時点での`print Dumper @a;`の結果

``` perl
$VAR1 = undef;
$VAR2 = [
          1,
          1,
          1,
          1,
          1,
          undef,
          1,
          1,
          undef,
          undef,
          1,
          1
        ];
$VAR3 = [
          undef,
          undef,
          undef,
          undef,
          1,
          undef,
          1
        ];
```

-   `pop @a` は末尾の配列(の参照)を返し、`$#{...}`はその長さを取り出す
