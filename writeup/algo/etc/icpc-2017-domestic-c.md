---
layout: post
redirect_from:
  - /blog/2017/07/14/icpc-2017-domestic-c/
date: "2017-07-14T23:50:37+09:00"
tags: [ "competitive", "writeup", "icpc", "icpc-domestic" ]
---

# ACM-ICPC 2017 国内予選: C. 池のある庭園

## solution

縦幅$d \le 10$かつ横幅$w \le 10$と小さい。
枠となる長方形を全て試し、内部についても愚直にやる。$O((dw)^3)$。

## implementation

本番にペアプロしたやつそのまま。

``` c++
#include <bits/stdc++.h>

using namespace std;

typedef long long ll;
const int inf = 1e9 + 7;

int main() {
    int h, w;
    while (cin >> h >> w) {
        if (h == 0 && w == 0) break;
        vector<vector<ll> > e(h, vector<ll> (w));
        for (int y = 0; y < h; y ++) {
            for (int x = 0; x < w; x ++) {
                cin >> e[y][x];
            }
        }
        ll ans = 0;
        for (int ly = 0; ly < h; ly ++) {
            for(int lx = 0; lx < w; lx ++) {
                for (int ry = ly + 2; ry < h; ry ++) {
                    for (int rx = lx + 2; rx < w; rx ++) { //[l, r]
                        ll sum = 0;
                        ll ma = 0, mi = inf;
                        for (int y = ly; y <= ry; y ++) {
                            mi = min(mi, e[y][lx]);
                            mi = min(mi, e[y][rx]);
                        }
                        for (int x = lx + 1; x <= rx - 1; x ++) {
                            mi = min(mi, e[ly][x]);
                            mi = min(mi, e[ry][x]);
                        }
                        for (int y = ly + 1; y <= ry - 1; y ++) {
                            for (int x = lx + 1; x <= rx - 1; x ++) {
                                ma = max(ma, e[y][x]);
                                sum += e[y][x];
                            }
                        }
                        if (mi > ma) ans = max(ans, mi * ((ry - ly - 1) * (rx - lx - 1)) - sum); 
                    }
                }
            }
        }
        cout << ans << endl;
    }
}
```
