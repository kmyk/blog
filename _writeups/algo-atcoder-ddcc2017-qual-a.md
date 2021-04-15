---
layout: post
redirect_from:
  - /writeup/algo/atcoder/ddcc2017-qual-a/
  - /blog/2017/11/10/ddcc2017-qual-a/
date: "2017-11-10T23:33:57+09:00"
tags: [ "competitive", "writeup", "atcoder", "ddcc", "sed" ]
"target_url": [ "https://beta.atcoder.jp/contests/ddcc2017-qual/tasks/ddcc2017_qual_a" ]
---

# DISCO presents ディスカバリーチャンネル コードコンテスト2017 予選: A - DDCC型文字列

## 感想

これはsed一択。私以外にも$3$人が本番でsedしてた。

## implementation

``` sed
#!/bin/sed -f
/.\(.\)\1./cNo
/\(.\)\1\(.\)\2/cYes
cNo
```
