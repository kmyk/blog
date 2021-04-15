---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_075_d/
  - /writeup/algo/atcoder/arc-075-d/
  - /blog/2017/06/03/arc-075-d/
date: "2017-06-03T22:57:59+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc075/tasks/arc075_b" ]
---

# AtCoder Regular Contest 075: D - Widespread

## solution

答え$m$を二分探索。
$mB$回の爆風で死なない$h\_i - mB \gt 0$な魔物に爆破の中心にしたときの増分$A-B$を追加で割り振っていって$m$回分で足りるかどうかを見る。
$O(N \log \max h\_i)$。

## implementation

にぶたんのテンプレ便利。

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
ll binsearch(ll l, ll r, function<bool (ll)> p) { // [l, r), p is monotone
    assert (l < r);
    -- l; -- r; // (l, r]
    while (l + 1 < r) {
        ll m = (l + r) / 2;
        (p(m) ? r : l) = m;
    }
    return r; // = min { x | p(x) }
}

int main() {
    int n, a, b; scanf("%d%d%d", &n, &a, &b);
    vector<int> h(n); repeat (i, n) scanf("%d", &h[i]);
    ll result = binsearch(0, *whole(max_element, h) + 1, [&](ll m) {
        ll cnt = 0;
        repeat (i, n) {
            ll x = h[i] - m * b;
            if (x >= 0) {
                cnt += (x + a-b-1) / (a-b);
            }
        }
        return cnt <= m;
    });
    printf("%lld\n", result);
    return 0;
}
```
