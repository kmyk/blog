---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_079_d/
  - /writeup/algo/atcoder/arc-079-d/
  - /blog/2017/07/29/arc-079-d/
date: "2017-07-29T23:07:09+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc079/tasks/arc079_b" ]
---

# AtCoder Regular Contest 079: D - Decrease (Contestant ver.)

Eが解けているとしてもなおFより難しい。
捨ててFに行っておけば脱色は避けられたはず。

## solution

E問題は解けているものとする。
上手く列$a$でその処理回数$\mathrm{decrease}(a)$が$K \le \mathrm{decrease}(a) = K + \epsilon$なものを構成する。$\epsilon \approx 100$ぐらいであれば、これは二分探索などで雑に作ることができる。
あとは$\epsilon$回処理をしてやると$\mathrm{decrease}(a') = K$な列$a'$が得られる。計算量は良く分からず。

$\mathrm{decrease}(a) = K + \epsilon$な列$a$の構成には、長さ$N$を適当に決め前から順に${10}^{16} + \delta$を埋めていき、$K$を越えるところで二分探索をすればよい。
ここで$\delta$は上手くとる。$500$ぐらい。大きすぎると$\epsilon$回の処理の前では$a\_i \le {10}^{16} + 1000$だが処理の後ではそうでなくなる場合がある。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

template <typename UnaryPredicate>
ll binsearch(ll l, ll r, UnaryPredicate p) { // [l, r), p is monotone
    assert (l < r);
    -- l;
    while (r - l > 1) {
        ll m = (l + r) / 2;
        (p(m) ? r : l) = m;
    }
    return r; // = min { x in [l, r) | p(x) }, or r
}

ll decrease_destructive(vector<ll> & a) {
    int n = a.size();
    ll result = 0;
    while (true) {
        bool modified = false;
        ll acc_k = 0;
        repeat (i, n) if (a[i] >= n) {
            ll k = a[i] / n;
            a[i] %= n;
            a[i] -= k;
            acc_k += k;
            result += k;
            modified = true;
        }
        repeat (j, n) a[j] += acc_k;
        if (not modified) break;
    }
    return result;
}
ll decrease(vector<ll> a) {
    return decrease_destructive(a);
}

constexpr ll max_a = 10000000000000000ll + 1000ll;
int main() {
    ll k; scanf("%lld", &k);
    int n = 2;
    while (decrease(vector<ll>(n, max_a)) < k) ++ n;
    vector<ll> a(n);
    repeat (i, n) {
        a[i] = max_a - 500;
        if (decrease(a) > k) {
            a[i] = 0;
            vector<ll> b = a;
            ll base = decrease_destructive(b);
            a[i] = binsearch(0, max_a - 500 + 1, [&](ll a_i) {
                vector<ll> c = b;
                c[i] += a_i;
                return base + decrease_destructive(c) >= k;
            });
            while (decrease(a) < k and a[i] < max_a - 500) {
                ll delta = decrease(a) - k;
                a[i] = min(max_a, a[i] - 500 + delta);
            }
        }
        if (decrease(a) >= k) break;
    }
    assert (decrease(a) >= k);
    ll delta = decrease(a) - k;
    while (delta --) {
        int i = whole(max_element, a) - a.begin();
        a[i] -= n;
        repeat (j, n) if (j != i) a[j] += 1;
    }
    assert (decrease(a) == k);
    assert (not a.empty());
    printf("%d\n", n);
    repeat (i, n) {
        printf("%lld%c", a[i], i + 1 == n ? '\n' : ' ');
        assert (a[i] <= max_a);
    }
    return 0;
}
```
