---
layout: post
redirect_from:
  - /blog/2018/02/14/yahoo-procon2018-qual-c/
date: "2018-02-14T20:15:26+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon", "dp", "bit-dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2018-qual/tasks/yahoo_procon2018_qual_c" ]
---

# 「みんなのプロコン 2018」: C - 駆引取引

勘違いにより時間が溶けた。

## solution

DP。財宝を$i$個売却しまだ販売されている商品の集合が$X$の時点から互いに最適に動いたときの得点の最大値を$\mathrm{dp}(i, X)$とする。
$i$の大きい方から決めていく。
財宝を売却する個数は最初に決めるのではないことに注意せよ。
$\mathrm{ans} = \mathrm{dp}(0, \\{ 1, 2, \dots, N \\})$であって、$\max \\{ f(i, X) \mid i \le N \land \|X\| = N - i \\}$のようなものではない。
$O(N^22^N)$。


## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

vector<ll> get_sum_x(vector<ll> const & x) {
    int n = x.size();
    vector<ll> sum_x(1 << n);
    REP3 (s, 1, 1 << n) {
        int i = __builtin_ctz(s);
        int t = s ^ (1 << i);
        sum_x[s] = sum_x[t] + x[i];
    }
    return sum_x;
}

int main() {
    // input
    int n; cin >> n;
    vector<ll> x(n); REP (i, n) cin >> x[i];
    vector<ll> c(n); REP (i, n) cin >> c[i];
    vector<ll> v(n); REP (i, n) cin >> v[i];

    // solve
    ll sum_x = accumulate(ALL(x), 0ll);
    auto sum_c = get_sum_x(c);
    auto sum_v = get_sum_x(v);
    vector<ll> cur(1 << n);
    vector<ll> prv(1 << n);
    REP_R (i, n) {
        sum_x -= x[i];
        // f : usable -> value
        vector<ll> f(1 << n);
        REP (s, 1 << n) {
            if (__builtin_popcount(s) <= n - i and sum_c[s] <= sum_x) {
                f[s] = sum_v[s];
            } else {
                REP (j, n) if (s & (1 << j)) {
                    int t = s ^ (1 << j);
                    chmax(f[s], f[t]);
                }
            }
        }
        // update dp
        cur.swap(prv);
        cur.assign(1 << n, LLONG_MAX);
        REP (s, 1 << n) {
            REP (j, n) if (s & (1 << j)) {
                int t = s ^ (1 << j);
                chmin(cur[s], prv[t]);
            }
            chmax(cur[s], f[s]);
        }
    }

    // output
    cout << cur[(1 << n) - 1] << endl;
    return 0;
}
```
