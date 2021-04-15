---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_078_c/
  - /writeup/algo/atcoder/arc-078-c/
  - /blog/2017/07/15/arc-078-c/
date: "2017-07-15T23:15:34+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc078/tasks/arc078_a" ]
---

# AtCoder Regular Contest 078: C - Splitting Pile

友人が

>   高々10^5の数字でも10^9個も足すと普通にオーバーフローするって事を学習しました。

って言っていました。みんな一度はやったことあるやつ。

## solution

$2$回舐める。まず総和を計算して、前から累積和を取って答え(の候補)を更新しつつもう$1$周。$O(N)$。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <numeric>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

int main() {
    int n; scanf("%d", &n);
    vector<ll> a(n); repeat (i, n) scanf("%lld", &a[i]);
    ll x = a[0];
    ll y = whole(accumulate, a, 0ll) - a[0];
    ll result = abs(x - y);
    repeat_from (i, 1, n - 1) {
        x += a[i];
        y -= a[i];
        setmin(result, abs(x - y));
    }
    printf("%lld\n", result);
    return 0;
}
```
