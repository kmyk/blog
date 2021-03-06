---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/180/
  - /blog/2016/09/22/yuki-180/
date: "2016-09-22T22:10:16+09:00"
tags: [ "competitive", "writeup", "yukicoder", "binary-search", "convex-function" ]
"target_url": [ "http://yukicoder.me/problems/no/180" ]
---

# Yukicoder No.180 美しいWhitespace (2)

三分探索にするとちょっと面倒。

## solution

一次関数の集合から定義される関数$f(x)$に対し、$\argmin\_{x \in \mathbb{N}^{+}} f(x)$を求める問題。
図を書くと$f(x)$は下に凸っぽいので、雑に微分して$\min \\{ x \mid f'(x) \ge 0 \\}$を二分探索するとよい。

上側の関数と下側の関数を反転した線の傾きは広義単調増加であり、その和の傾きも広義単調増加。
よって$f(x)$は凸関数である。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
ll binsearch(ll l, ll r, function<bool (ll)> p) { // [l, r), p is monotone
    assert (l < r);
    -- l; -- r; // (l, r]
    while (l + 1 < r) {
        ll m = (l + r + 1) / 2;
        (p(m) ? r : l) = m;
    }
    return r; // = min { x | p(x) }
}
const ll inf = ll(1e18)+9;
int main() {
    int n; cin >> n;
    vector<int> a(n), b(n); repeat (i,n) cin >> a[i] >> b[i];
    auto f = [&](ll x) {
        ll l = inf, r = 0;
        repeat (i,n) {
            setmin(l, a[i] + b[i]*x);
            setmax(r, a[i] + b[i]*x);
        }
        return r - l;
    };
    ll limit = *whole(max_element, a) + 2;
    ll ans = binsearch(1, limit, [&](ll x) {
        return f(x) <= f(x+1);
    });
    cout << ans << endl;
    return 0;
}
```
