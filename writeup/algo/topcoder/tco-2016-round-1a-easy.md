---
layout: post
redirect_from:
  - /blog/2016/03/27/tco-2016-round-1a-easy/
date: 2016-03-27T04:16:49+09:00
tags: [ "competitive", "writeup", "topcoder", "tco" ]
---

# TopCoderOpen 2016 round 1A Easy: EllysTimeMachine

やるだけ。

同じ変換を再度行うと元に戻るので、これを使えばほぼでテストケースが$6$つ増える。

## 問題

$[0,12)$の2つの整数$(a,b)$による時間の表現で以下のようなものを考える。

-   $(a,b)$は$a+1$時$5b$分を表す。

時刻の文字列表現`HH:MM`が与えられる。これの整数対$(a,b)$による表現を考え、$(b,a)$で表現される時刻を文字列表現`HH:MM`に変換せよ。

## 実装

``` c++
#include <bits/stdc++.h>
using namespace std;
class EllysTimeMachine { public: string getTime(string time); };
string EllysTimeMachine::getTime(string time) {
    int h = (time[0] - '0') * 10 + (time[1] - '0');
    int m = (time[3] - '0') * 10 + (time[4] - '0');
    swap(h, m);
    h /= 5;
    m *= 5;
    if (h ==  0) h = 12;
    if (m == 60) m = 0;
    time[0] = (h / 10) + '0';
    time[1] = (h % 10) + '0';
    time[3] = (m / 10) + '0';
    time[4] = (m % 10) + '0';
    return time;
}
```
