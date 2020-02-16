---
layout: post
alias: "/blog/2017/12/31/utpc-2012-e/"
date: "2017-12-31T17:56:01+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder" ]
"target_url": [ "https://beta.atcoder.jp/contests/utpc2012/tasks/utpc2012_05" ]
---

# 東京大学プログラミングコンテスト2012: E - 選挙

## solution

二分探索ではない。
議員定数全体が増加したのに議席が減る減少はAlabama paradoxと呼ばれ、今回はこれが起こりうる。
適当に除算などして良い下界を求め、条件を満たすまで$1$ずつincrementしていくのが正解。
$s = \sum a\_i$増やせばどの政党も議席が$1$以上増えることを使えば$O(s N \log N)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n), b(n); REP (i, n) scanf("%d%d", &a[i], &b[i]);
    // solve
    int s = accumulate(ALL(a), 0);
    auto pred = [&](ll m) {
        vector<ll> c(n);
        vector<pair<ll, int> > order(n);
        ll remainder = m;
        REP (i, n) {
            c[i] = a[i] * m / s;
            if (c[i] < b[i] - 1) return false;
            order[i] = { - a[i] * m % s, i };
            remainder -= c[i];
        }
        assert (remainder < n);
        sort(ALL(order));
        REP (i, remainder) {
            c[order[i].second] += 1;
        }
        REP (i, n) {
            if (c[i] < b[i]) {
                return false;
            }
        }
        return true;
    };
    ll m = accumulate(ALL(b), 0ll);
    REP (i, n) {
        chmax<ll>(m, b[i] *(ll) s / a[i] - s);
    }
    while (not pred(m)) ++ m;
    // output
    printf("%lld\n", m);
    return 0;
}
```
