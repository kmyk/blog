---
layout: post
redirect_from:
  - /blog/2016/03/19/arc-049-b/
date: 2016-03-19T23:37:24+09:00
tags: [ "competitive", "writeup", "atcoder", "binary-search" ]
---

# AtCoder Regular Contest 049 B - 高橋ノルム君

## [B - 高橋ノルム君](https://beta.atcoder.jp/contests/arc049/tasks/arc049_b)

### 解法

二分探索。$O(N^2\log N)$。

一点に集まるために必要な最小の時間、を達成するような点は、全ての初期位置から時間$t$以内に到達可能な点である。
逆にそのような最小の時間とは、そのような点が存在するような時間の中で最小のものである。
その点の存在は、任意のふたつの初期位置に関して、それぞれそこから出発して時間$t$以内に集まることができる、で判定できる。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <cstdio>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int n; cin >> n;
    vector<ll> x(n), y(n), c(n); repeat (i,n) cin >> x[i] >> y[i] >> c[i];
    vector<double> v(n); repeat (i,n) v[i] = 1.0 / c[i];
    auto do_intersect = [&](int i, int j, double t) {
        return max(abs(x[i] - x[j]), abs(y[i] - y[j])) <= (v[i] + v[j]) * t;
    };
    double low = 0, high = 1e18;
    repeat (iteration,100) {
        double mid = (low + high) / 2;
        bool p = true;
        repeat (i,n) repeat (j,i) {
            if (not do_intersect(i, j, mid)) {
                p = false;
                goto a_break;
            }
        }
a_break:
        (p ? high : low) = mid;
    }
    printf("%.8lf\n", low);
    return 0;
}
```
