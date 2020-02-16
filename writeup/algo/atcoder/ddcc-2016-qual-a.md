---
layout: post
alias: "/blog/2016/11/05/ddcc-2016-qual-a/"
date: "2016-11-05T22:26:09+09:00"
tags: [ "competitive", "writeup", "atcoder", "ddcc", "golf", "perl" ]
"target_url": [ "https://beta.atcoder.jp/contests/ddcc2016-qual/tasks/ddcc_2016_qual_a" ]
---

# DISCO presents ディスカバリーチャンネル コードコンテスト2016 予選: A - SDカード

## implementation

### perl 24byte

``` perl
<>=~/ .* /;print$'*$&/$`
```

## 検討

-   awkで$21$byte ([hanada3355さん](https://beta.atcoder.jp/contests/ddcc2016-qual/submissions/967091))
-   `$/=$"`で空白区切り読み込みで$22$byte ([cielさん](https://beta.atcoder.jp/contests/ddcc2016-qual/submissions/967320), [%20さん](https://beta.atcoder.jp/contests/ddcc2016-qual/submissions/967502))
