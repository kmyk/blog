---
redirect_from:
  - /writeup/algo/atcoder/cf18-relay-j/
layout: post
date: 2018-11-21T11:28:54+09:00
tags: [ "competitive", "writeup", "atcoder", "code-festival", "dp", "cumulative-sum" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf18-relay-open/tasks/relay2018_j" ]
---

# Code Festival (2018) Team Relay: J - 健康診断

## 解法

### 概要

DP。最後に狼(`A`)と狐(`B`)のどちらを使ったかを持ちながら端から順番に見ていく。
$$r \lt n$$ に対し $$\mathrm{dp} _ A (r) = \min \left( \left\{ \sum_j (r - j) b_j \right\} \cup \left\{ \mathrm{dp} _ B (l) + \sum_i (i - l + 1) b_i + \sum_j (r - j) b_j \mid 0 < l < r \right\} \right)$$ のような形の漸化式になる。
$O(N^2)$ あるいは $O(N^2 \log N)$。

## メモ

本番で担当したが詰めが甘く、落とした

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;
template <class T, class U> inline void chmin(T & a, U const & b) { a = min<T>(a, b); }

class linear_weighted_sum {
    vector<ll> b;
    vector<ll> c;
public:
    linear_weighted_sum() = default;
    linear_weighted_sum(vector<ll> const & a) {
        int n = a.size();
        b.resize(n + 1);
        c.resize(n + 1);
        REP (i, n) {
            b[i + 1] = b[i] + a[i];
            c[i + 1] = c[i] + i * a[i];
        }
    }
    ll range_sum(int l, int r) const {
        assert (max(0, l) <= r and r <= b.size() - 1);
        int l1 = max(0, l);
        return (c[r] - c[l1]) - l * (b[r] - b[l1]);
    }
    ll inversed_range_sum(int l, int r) const {
        assert (0 <= l and l <= min((int)b.size() - 1, r));
        int r1 = min((int)b.size() - 1, r);
        return r * (b[r1] - b[l]) - (c[r1] - c[l]);
    }
};

ll solve(int n, vector<ll> const & a, vector<ll> const & b) {
    vector<ll> dp_a(n + 1, LLONG_MAX);
    vector<ll> dp_b(n + 1, LLONG_MAX);
    linear_weighted_sum lws_a(a);
    linear_weighted_sum lws_b(b);
    REP3 (r, 1, n) {
        chmin(dp_a[r], lws_b.inversed_range_sum(0, r));
        chmin(dp_b[r], lws_a.inversed_range_sum(0, r));
        REP3 (l, 1, r) {
            int m = (l + r) / 2;
            chmin(dp_a[r], dp_b[l] + lws_b.range_sum(l - 1, m) + lws_b.inversed_range_sum(m, r));
            chmin(dp_b[r], dp_a[l] + lws_a.range_sum(l - 1, m) + lws_a.inversed_range_sum(m, r));
        }
    }
    REP3 (l, 1, n) {
        chmin(dp_a[n], dp_b[l] + lws_b.range_sum(l - 1, n));
        chmin(dp_b[n], dp_a[l] + lws_a.range_sum(l - 1, n));
    }
    return min(dp_a[n], dp_b[n]);
}

int main() {
    int n; cin >> n;
    vector<ll> a(n), b(n);
    REP (i, n) cin >> a[i] >> b[i];
    cout << solve(n, a, b) << endl;
    return 0;
}
```
