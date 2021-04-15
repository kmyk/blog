---
layout: post
redirect_from:
  - /writeup/golf/yukicoder/163/
  - /blog/2017/01/26/yuki-163/
date: "2017-01-26T22:43:17+09:00"
tags: [ "competitive", "writeup", "yukicoder", "golf", "vimscript" ]
"target_url": [ "http://yukicoder.me/problems/no/163" ]
---

# Yukicoder No.163 cAPSlOCK

golfで勝つのにvimLを覚えないといけない時代が来ていたらしい。

## problem

`tr A-Za-z a-zA-Z` ($16$byte) する問題。

## 鑑賞

yozaさんによるvimscript $9$byte解: <http://yukicoder.me/submissions/138246>

``` vim
norm V~
p
```

-   `norm`は`:norm[al][!] {commands}`で、ノーマルモードのコマンドを実行。
-   `V`は`[count]V`で、行単位ビジュアルモードへ移行。
-   `~`は`{Visual}~`で、選択範囲のケースを反転。
-   `p`は`:[range]p[rint] [flags]`で、その行を出力。
