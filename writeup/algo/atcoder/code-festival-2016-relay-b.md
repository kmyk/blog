---
layout: post
alias: "/blog/2016/11/30/code-festival-2016-relay-b/"
date: "2016-11-30T01:33:18+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "golf", "perl" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-relay-open/tasks/relay_b" ]
---

# CODE FESTIVAL 2016 Relay: B - 鏡文 / Mirror String

hanada3355さんが自明に$1$byte縮む解を出してたから提出しなおした。
%20さんのも気になったから弄ったら$1$byte縮んだ。両方$47$byteの暫定最短になった。

## implementation

私が何も見ずに書いたperl $51$byte。

``` perl
s/\n//,print(reverse cmp y/bdpq/dbqp/r?No:Yes)for<>
```

%20さんの提出は同様の方向性の$48$byteで、`$_=$/.<>`で先頭に改行を付与し、`cmp`でなく`=~`で一致判定するもの。
