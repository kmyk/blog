---
redirect_from:
layout: post
date: 2018-07-02T20:13:39+09:00
tags: [ "competitive", "writeup", "atcoder", "codeflyer", "cumulative-sum", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/bitflyer2018-final-open/tasks/bitflyer2018_final_b" ]
---

# codeFlyer （bitFlyer Programming Contest）: B - 交通費

## solution

区分的に線形である(典型)ので適当にやる。$O(N \log N + Q \log N)$。

<span>$f(c, d) = \sum_{i \in N} \min \\{ d, | X_i - c | \\}$</span> を$Q$回計算する問題。
非線形関数$\min$と<span>$| \cdot |$</span>を展開すれば$4$個の線形関数の和に分解できる。
前処理として$X_i$の整列や累積和をし、$(c, d)$ごとに区切りを二分探索すれば、これは$1$回あたり$O(\log N)$で計算できる。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

int main() {
    // input
    int n, q; cin >> n >> q;
    vector<ll> x(n);
    REP (i, n) cin >> x[i];
    vector<ll> c(q), d(q);
    REP (j, q) cin >> c[j] >> d[j];

    // solve
    vector<ll> acc_x(n + 1);
    partial_sum(ALL(x), acc_x.begin() + 1);
    REP (j, q) {
        int  l = lower_bound(ALL(x), c[j] - d[j]) - x.begin();
        int cl = lower_bound(ALL(x), c[j]       ) - x.begin();
        int cr = upper_bound(ALL(x), c[j]       ) - x.begin();
        int  r = upper_bound(ALL(x), c[j] + d[j]) - x.begin();
        ll answer = 0;
        answer += d[j] * l;
        answer += c[j] * (cl - l) - (acc_x[cl] - acc_x[l]);
        answer += (acc_x[r] - acc_x[cr]) - c[j] * (r - cr) ;
        answer += d[j] * (n - r);

        // output
        cout << answer << endl;
    }
    return 0;
}
```
