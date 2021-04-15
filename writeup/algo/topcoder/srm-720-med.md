---
layout: post
redirect_from:
  - /writeup/algo/topcoder/srm-720-med/
  - /blog/2017/08/25/srm-720-med/
date: "2017-08-25T22:02:56+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "dp", "combination" ]
---

# TopCoder SRM 720 Div1 Medium: DistinctGrid

実質Easy。頭が悪いので落とした。$-134$した。

## solution

常に$nk + 1$種類の数字が使える。$k \le \frac{n}{2}$なので、$1$行ごとにずらすようにしても被らない。$O(n^2)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
class DistinctGrid { public: vector<int> findGrid(int n, int k); };

vector<int> DistinctGrid::findGrid(int n, int k) {
    vector<int> f(n * n);
    if (k == 1) return f;
    int cnt = 1;
    repeat (y, n) {
        repeat (x, k - 1) {
            f[y * n + (y + x) % n] = cnt ++;
        }
    }
    return f;
}
```
