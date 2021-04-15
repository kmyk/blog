---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/414/
  - /blog/2016/08/26/yuki-414/
date: "2016-08-26T23:45:02+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/414" ]
---

# Yukicoder No.414 衝動

$\sqrt{M}$まで試し割りすればよいので$O(\sqrt{M})$。

なんとなく`factor`に投げてみたが、普通に書いた方が楽だったと思う。
何かの拍子にWAになって再提出になりそうだし。

``` sh
#!/bin/bash
read line
a=1
b=1
for n in `factor $line | cut -d: -f 2` ; do
    if [ $a -eq 1 ] ; then
        a=$[$a * $n]
    else
        b=$[$b * $n]
    fi
done
echo $a $b
```
