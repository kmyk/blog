---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/167/
  - /blog/2016/12/20/yuki-167/
date: "2016-12-20T00:24:00+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/167" ]
---

# Yukicoder No.167 N^M mod 10

[No.467 隠されていたゲーム](http://yukicoder.me/problems/no/467)のeditorialで紹介されてためぐるちゃんの[解説](http://twilog.org/meguru_comp/search?word=%E3%80%90yukicoder%20No.167%E3%80%91&ao=a)が面白かったので解いた。
CTFの暗号問っぽさをすこし感じる。

## solution

modにより発生する周期性。$O(1)$。

```
>>> for k in range(10): print(k, [ (k**i)%10 for i in range(20) ])
... 
0 [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
1 [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
2 [1, 2, 4, 8, 6, 2, 4, 8, 6, 2, 4, 8, 6, 2, 4, 8, 6, 2, 4, 8]
3 [1, 3, 9, 7, 1, 3, 9, 7, 1, 3, 9, 7, 1, 3, 9, 7, 1, 3, 9, 7]
4 [1, 4, 6, 4, 6, 4, 6, 4, 6, 4, 6, 4, 6, 4, 6, 4, 6, 4, 6, 4]
5 [1, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5]
6 [1, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6]
7 [1, 7, 9, 3, 1, 7, 9, 3, 1, 7, 9, 3, 1, 7, 9, 3, 1, 7, 9, 3]
8 [1, 8, 4, 2, 6, 8, 4, 2, 6, 8, 4, 2, 6, 8, 4, 2, 6, 8, 4, 2]
9 [1, 9, 1, 9, 1, 9, 1, 9, 1, 9, 1, 9, 1, 9, 1, 9, 1, 9, 1, 9]
```

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
m = int(input())
print(pow(n % 10, m % 4 + 4, 10) if m else 1)
```
