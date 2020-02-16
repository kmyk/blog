---
layout: post
alias: "/blog/2016/07/04/abc-041-b/"
date: "2016-07-04T04:49:53+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc", "golf", "ruby" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc041/submissions/790843" ]
---

# AtCoder Beginner Contest 041 B - 直方体

## implementation

### ruby 37byte

``` ruby
#!ruby -an
p eval($F*?*)%(1e9+7).to_i
```

%20さんの提出が$30$byteで$1$位だった(<https://beta.atcoder.jp/contests/abc041/submissions/790843>)。``` `tr \\  \\*` ```は賢い。
