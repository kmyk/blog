---
layout: post
redirect_from:
  - /blog/2016/05/20/s8pc-2-a/
date: 2016-05-20T14:20:07+09:00
tags: [ "competitive", "writeup", "atcoder", "golf", "s8pc" ]
"target_url": [ "https://beta.atcoder.jp/contests/s8pc-2/tasks/s8pc_2_a" ]
---

# square869120Contest #2 A - IOI列車で行こう2

## implementation

### 私 perl 36byte

``` perl
#!perl -pl
$_=s/O*I//*(2*s/OI//g+1)
```

``` perl
$_=<>;print s/O*I//*(2*s/OI//g+1),$/
```

`O*I`で先頭を削って、削れたならばさらに`O+I+`の数を数える。
これはmatchの順序の関係で`OI`としてよい。

### hanada3355さん bash 33byte

``` bash
tr O \ |awk '$0=(NF?NF:.5)*2-1""'
```

`O`空白で置換することで`I`の繰り返しからなる単語の列となる。
単語数`NF`を使って計算している。`NF`が$0$の時は$1$にする。

``` bash
tr O \ |awk '$0=(NF?NF*2-1:0)""'
```

とすると1B縮む。

### climpetさん perl 30byte

``` perl
@a=<>=~/I+/g;print@a*2-!!@a,$/
```

方針は同じで、`I+`にmatchする部分を全て取り出し、その数を使って計算している。

``` perl
@a = (<> =~ /I+/g);
print(@a*2 - !!@a, $/);
```
