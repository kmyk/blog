---
layout: post
alias: "/blog/2016/03/30/arc-048-a/"
title: "AtCoder Regular Contest 048 A - 階段の下"
date: 2016-03-30T13:20:58+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "golf" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc048/tasks/arc048_a" ]
---

perl 31byte

``` perl
<>=~/ /;print$'-$`-($'*$`<0),$/
```

`/ /`を`$"`(単一の空白文字)にすればさらに1byte縮む。(climpet氏の[提出](https://beta.atcoder.jp/contests/arc048/submissions/653618)、%20氏の[提出](https://beta.atcoder.jp/contests/arc048/submissions/653334))

1位はbashからawkを呼んだ%20氏の[提出](https://beta.atcoder.jp/contests/arc048/submissions/653351)の24byteだった。
