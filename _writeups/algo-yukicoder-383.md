---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/383/
  - /blog/2016/07/02/yuki-383/
date: 2016-07-02T00:23:12+09:00
tags: [ "competitive", "writeup", "yukicoder", "sed" ]
"target_url": [ "http://yukicoder.me/problems/no/383" ]
---

# Yukicoder No.383 レーティング

類問:

-   <http://golf.shinh.org/p.rb?A+plus+B+problem>
-   <http://golf.shinh.org/p.rb?Comparing+two+numbers>

## implementation

### sed 160byte

``` sed
#!/bin/sed -f
:
s/[1-9]/&s/g
y/123456789/012345678/
s/s0/9s/
t
s/\(.\)0/\1/
t
:0
s/s s/ /
t0
/s /s/^/-/
/ s/s/^/+/
s/ //
:1
s/s/<<123456789s01>/
s/\(.\)<.*\1\(s*.\).*>/\2/
t1
```
