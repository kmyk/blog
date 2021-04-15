---
layout: post
redirect_from:
  - /writeup/golf/anarchy-golf/join-lines/
  - /blog/2016/02/24/anagol-join-lines/
date: 2016-02-24T05:07:59+09:00
tags: [ "writeup", "golf", "anarchy-golf" ]
---

# Anarchy Golf 55. join lines

## [join lines](http://golf.shinh.org/p.rb?join+lines)

単純な課題なので簡単に1位と同じ長さになる。

``` perl
#!perl -p
chop
```

``` ruby
#!ruby -p
chop
```

``` brainfuck
,+[-----------[++++++++++.>],+]
```

``` sed
:
N
s/\n//
t
```

sedの`t`は`b`でもよい。(終端で`N`するとexitするため。)

>   If there is no more input then sed exits without processing any more commands.


c言語に関して、分からなかったので答えを見た。
変数名などを同一視すれば全て以下と同じであった。
私の環境では動かなかった。

``` c
main(s){for(;~printf(gets(&s)););}
```
