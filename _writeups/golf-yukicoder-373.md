---
layout: post
redirect_from:
  - /writeup/golf/yukicoder/373/
  - /blog/2016/06/05/yuki-373/
date: 2016-06-05T01:26:04+09:00
tags: [ "competitive", "writeup", "yukicoder", "golf", "perl" ]
"target_url": [ "http://yukicoder.me/problems/748" ]
---

# Yukicoder No.373 かけ算と割った余り

### python

``` python
#!/usr/bin/env python3
a, b, c, d = map(int,input().split())
print(a * b * c % d)
```

### perl 45byte

``` perl
($a,$b,$c,$d)=split$",<>;print $a*$b%$d*$c%$d
```

### tailsさん perl 35byte

<http://yukicoder.me/submissions/95737>

``` perl
use bigint;$/=$";print<>*1*<>*<>%<>
```

`$/=$"`は区切り文字を改行から空白にして、行ごとでなく単語ごとに読むようにする。
