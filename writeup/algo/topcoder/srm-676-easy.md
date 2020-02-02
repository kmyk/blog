---
layout: post
alias: "/blog/2015/12/19/srm-676-easy/"
title: "TopCoder SRM 676 Div1 Easy: WaterTank"
date: 2015-12-19T02:32:00+09:00
tags: [ "competitive", "writeup", "srm", "binary-search" ]
---

## [Easy: WaterTank]()

### 解説

単に二分探索すればよい。$O(n \log x)$。

タンクの水量の変化は、タンクに入る水の量の変化する時点(とタンクが空になる時点)を頂点とした折れ線グラフになるので、単にその頂点で限界$C$を越えているかのみを見ればよい。

### 実装

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
class WaterTank {
public:
    double minOutputRate(vector<int> t, vector<int> x, int C) {
        int n = t.size();
        double l = 0, r = *max_element(x.begin(), x.end());
        while (r - l > 1e-8) {
            double m = (l + r) / 2;
            bool ok = true;
            double water = 0;
            repeat (i,n) {
                water += t[i] * (x[i] - m);
                water = max(0.0, water);
                if (C < water) {
                    ok = false;
                    break;
                }
            }
            (ok ? r : l) = m;
        }
        return l;
    }
};
```
