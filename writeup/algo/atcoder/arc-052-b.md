---
layout: post
redirect_from:
  - /blog/2016/05/15/arc-052-b/
date: 2016-05-15T06:32:02+09:00
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc052/tasks/arc052_b" ]
---

# AtCoder Regular Contest 052 B - 円錐

## solution

$O(QN)$で愚直にやる。

底面の位置を動かして足して引いてをする。
$v(r,h) = \frac{\pi r^2 h}{3}$である。

## implementation

``` c++
#define _USE_MATH_DEFINES
#include <iostream>
#include <vector>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int n, q; cin >> n >> q;
    vector<ll> x(n), r(n), h(n); repeat (i,n) cin >> x[i] >> r[i] >> h[i];
    vector<double> v(n); repeat (i,n) v[i] = M_PI * pow(r[i],2) * h[i] / 3;
    auto v_from = [&](int i, ll l) {
        double nh = x[i] + h[i] - l;
        return v[i] * pow(nh / h[i], 3);
    };
    while (q --) {
        ll a, b; cin >> a >> b;
        double ans = 0;
        repeat (i,n) {
            if (a <= x[i] + h[i]) ans += v_from(i, max(a, x[i]));
            if (b <= x[i] + h[i]) ans -= v_from(i, max(b, x[i]));
        }
        cout << ans << endl;
    }
    return 0;
}
```
