---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2017-qualc-a/
  - /blog/2018/01/01/code-festival-2017-qualc-a/
date: "2018-01-01T12:14:00+09:00"
tags: [ "competitive", "writeup", "codefestival", "sed", "golf" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2017-qualc/tasks/code_festival_2017_qualc_a" ]
---

# CODE FESTIVAL 2017 qual C: A - Can you get AC?

早解きの意味でもsed一択。

## implementation

``` sed
#!/bin/sed -f
/AC/cYes
cNo
```
