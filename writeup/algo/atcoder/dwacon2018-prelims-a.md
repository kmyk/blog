---
layout: post
redirect_from:
  - /blog/2018/01/14/dwacon2018-prelims-a/
date: "2018-01-14T03:41:52+09:00"
tags: [ "competitive", "writeup", "atcoder", "dwacon", "sed", "golf" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2018-prelims/tasks/dwacon2018_prelims_a" ]
---

# 第4回 ドワンゴからの挑戦状 予選: A - ニコニコ文字列判定

perlで$s \bmod 101 =  0$を判定する頭の良い$18$byte解も出ていたが提出速度差で最短を回収。
この内容だとコンテスト中でもsed一択。

## implementation

sed $18$byte。

``` sed
/\(..\)\1/cYes
cNo
```
