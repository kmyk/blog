---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/545/
  - /blog/2017/07/15/yuki-545/
date: "2017-07-15T02:34:09+09:00"
tags: [ "competitive", "writeup", "yukicoder", "meet-in-the-middle" ]
---

# Yukicoder No.545 ママの大事な二人の子供

サンプルが弱いようには見えないがなぜかすり抜け$2$WAを生やした。

## solution

半分全列挙。$A\_i$と$- B\_i$のどちらかを選んで足し合わせると言い換えて、絶対値を$0$に近付けるようにする。$O(2^\frac{N}{2})$。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <climits>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

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

vector<ll> calc_sums(int l, int r, vector<ll> const & a, vector<ll> const & b) {
    vector<ll> cur, prv;
    cur.push_back(0);
    repeat_from (i, l, r) {
        cur.swap(prv);
        cur.clear();
        for (ll x : prv) {
            cur.push_back(x + a[i]);
            cur.push_back(x - b[i]);
        }
    }
    whole(sort, cur);
    cur.erase(whole(unique, cur), cur.end());
    return cur;
}

ll solve(int n, vector<ll> const & a, vector<ll> const & b) {
    if (n == 1) {
        return min(a[0], b[0]);
    }
    vector<ll> left  = calc_sums(0, n / 2, a, b);
    vector<ll> right = calc_sums(n / 2, n, a, b);
    ll result = LLONG_MAX;
    for (ll x : left) {
        int i = binsearch(0, right.size(), [&](int i) {
            return x + right[i] >= 0;
        });
        for (int di = -1; di <= +1; ++ di) {
            if (0 <= i + di and i + di < right.size()) {
                setmin(result, abs(x + right[i + di]));
            }
        }
    }
    return result;
}

int main() {
    int n; scanf("%d", &n);
    vector<ll> a(n), b(n); repeat (i, n) scanf("%lld%lld", &a[i], &b[i]);
    ll result = solve(n, a, b);
    printf("%lld\n", result);
    return 0;
}
```
