---
layout: post
redirect_from:
  - /writeup/algo/topcoder/tco-2016-round-1a-med/
  - /blog/2016/03/27/tco-2016-round-1a-med/
date: 2016-03-27T04:17:09+09:00
tags: [ "competitive", "writeup", "topcoder", "tco", "binary-search" ]
---

# TopCoderOpen 2016 round 1A Medium: EllysSocks

最大の最小みたいな問題はにぶたん。
mediumにしては簡単だった。

## 問題

整数の列$S$が与えられる。$S$の項を使って$P$個の整数の対を作る。
そのような対の集まり$X = \\{ (a_i,b_i) | 0 \le i \lt P \\}$に関して、対を成す数の差の最大値$D_X = \max_i \| a_i - b_i \|$を考え、この最小値$\min_X D_X$を答えよ。

## 解法

二分探索。その述語はsortして貪欲。

## 実装

off-by-oneのあたりはサンプルが通るように適当に合わせた。

``` c++
#include <bits/stdc++.h>
typedef long long ll;
using namespace std;
class EllysSocks { public: int getDifference(vector<int> S, int P); };
int EllysSocks::getDifference(vector<int> s, int p) {
    sort(s.begin(), s.end());
    ll low = 0, high = 10000000001;
    while (low + 1 < high) {
        ll mid = (low + high) / 2;
        int cnt = 0;
        int prv = -1;
        for (int it : s) {
            if (prv != -1 and (it - prv) < mid) {
                cnt += 1;
                prv = -1;
            } else {
                prv = it;
            }
        }
        (p <= cnt ? high : low) = mid;
    }
    return low;
}
```
