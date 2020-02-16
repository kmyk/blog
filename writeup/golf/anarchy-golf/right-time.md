---
layout: post
alias: "/blog/2016/02/25/anagol-right-time/"
date: 2016-02-25T02:57:37+09:00
tags: [ "writeup", "anarchy-golf", "golf", "time" ]
---

# Anarchy Golf 53. right time

閏秒の処理が分からなかった。閏秒を無視してperlで単純に`-pl`で`gmtime`して`strftime`するだけで49byteになって、1位まで残り18byteしか空きがなく、検索ゲーはあまり楽しくないので放棄した。

## [right time](http://golf.shinh.org/p.rb?right+time)

以下全部、環境変数`$TZ`に`right/XX`を設定している。
出題は2007年3月であるが、これ以降に挿入された閏秒が存在するため、現在提出してもWAになるだろう。

### ySas氏 perl 67byte

``` perl
use POSIX;$ENV{TZ}='right/NZ';print strftime"%F %T
",gmtime$_ for<>
```

`"%F %T\n"`を`'%F %T\n'`で置き換えると、`strftime`との間に空白が必要。

### eban氏 perl 68byte

``` perl
#!perl -lp
use POSIX;$ENV{TZ}="right/GB";$_=strftime"%F %T",gmtime$_
```

### shinh氏 ruby 66byte

``` ruby
puts Time.at(eval gets).strftime'%F %X'while ENV["TZ"]="right/UTC"
```

`gets.to_i`でなく`eval gets`とすることで、EOFにより`nil`が返った際に例外で落としている。`nil.to_i`は`0`なので止まらない。

### eban氏 bash 40byte

``` sh
TZ=right/UTC xargs -i date -d@{} +%F\ %T
```
