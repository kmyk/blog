---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/212/
  - /blog/2016/11/22/yuki-212/
date: "2016-11-22T21:05:13+09:00"
tags: [ "competitive", "writeup", "yukicoder", "expected-value" ]
"target_url": [ "http://yukicoder.me/problems/442" ]
---

# Yukicoder No.212 素数サイコロと合成数サイコロ (2)

確率変数$X,Y$が独立ならば$E[XY] = E[X]E[Y]$。よく言う期待値の線形性とは、独立であるかに関わらず$E[X+Y] = E[X]+E[Y]$であるという性質。

前者をすっかり忘れていたことを告白しておきたい。

``` python
#!/usr/bin/env python3
p, c = map(int, input().split())
dice_p = [ 2,3,5,7,11,13 ]
dice_c = [ 4,6,8,9,10,12 ]
ans = pow(sum(dice_p)/6, p) * pow(sum(dice_c)/6, c)
print('%.12f' % ans)
```
