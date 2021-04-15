---
redirect_from:
  - /writeup/algo/etc/icpc-2018-domestic-practice-f/
layout: post
date: 2018-07-01T23:59:04+09:00
tags: [ "competitive", "writeup", "icpc-domestic", "dp", "imos-method" ]
"target_url": [ "http://acm-icpc.aitea.net/index.php?2018%2FPractice%2F%E6%A8%A1%E6%93%AC%E5%9B%BD%E5%86%85%E4%BA%88%E9%81%B8%2F%E5%95%8F%E9%A1%8C%E6%96%87%E3%81%A8%E3%83%87%E3%83%BC%E3%82%BF%E3%82%BB%E3%83%83%E3%83%88" ]
---

# ACM-ICPC 2018 模擬国内予選: F. 対空シールド

## 解法

シールド$1, \dots, M - 1$だけのまま高階imos法で$O(M + N)$の前処理。シールド$M$の位置を最悪$O(N^2)$でやればかなり高速に通る。

$u \in N$番目のユニットの強さは式<span>$f(u, x_{M-1}) = \sum_{i \in M} \mathrm{max}(0, a_i - (x_i - u)^2)$</span>である。
<span>$x_{M-1}$</span>以外はすべて固定されているので適当な$b_u$に対し<span>$f(u, x_{M-1}) = \mathrm{max}(0, a_{M-1} - (x_{M-1} - u)^2) + b_u$</span>。
まずはこの<span>$b_u$</span>を求めたい。
$O(MN)$で遅いが愚直には、シールド$i \in M$のそれぞれについて、すべてのユニット$u \in N$に対し<span>$b_u \gets b_u + \mathrm{max}(0, a_i - (x_i - u)^2)$</span>と更新。
<span>$a_i \le 10^9$</span>のため計算量は落ちないが、ユニットを舐める範囲を絞れば更新式を<span>$b_u \gets b_u + a_i - (x_i - u)^2$</span>にできる。
これは高階のimos法を用いることのできる形なので<span>$b_u$</span>は解決。

<span>$b_u$</span>が出れば目的関数<span>$g(x_{M-1}) = \min \\{ f(u, x_{M-1}) \mid u \in N \\}$</span>は$O(N)$で求まる。
ユニットを調べる順番を<span>$b_u$</span>の順にすれば高速化が期待でき、試しに実装してみると間に合う。
列<span>$b_u$</span>の作り方が特殊なことを使えば何か証明できる可能性はある。

## note

高階imos法で無理矢理に線形性みたいなのが出てくるの気付いてなかった。
「線形になるまで微分すれば線形」という話なのでよく考えたら自明なんだけど面白い。

入力を覗き見ると大きなケースはひとつだけなので勇気を持って実装をしましょう。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define REP3R(i, m, n) for (int i = int(n) - 1; (i) >= int(m); -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
ll sq(ll x) { return x * x; }

ll solve(int n, int m, vector<int> const & a, vector<int> const & x) {
    // compute strength without last shield, using imos O(N + M)
    constexpr int D = 3;
    vector<ll> strength(n);
    vector<array<ll, D> > strength_fwd(n + 1);  // imos
    vector<array<ll, D> > strength_bck(n + 1);  // imos
    REP (i, m - 1) {
        strength[x[i]] += a[i];
        int sqrt_a = ceil(sqrt(a[i]));
        // forward
        int r = min(n, x[i] + sqrt_a);  // [x_i + 1, r)
        if (x[i] + 1 < r) {
            strength_fwd[x[i] + 1][0] += a[i];
            strength_fwd[r       ][0] -= a[i];
            strength_fwd[x[i] + 1][1] -= 1;
            strength_fwd[x[i] + 1][2] -= 2;
            strength_fwd[r       ][0] += sq(r - x[i] - 1);
            strength_fwd[r       ][1] += 2 * (r - x[i] - 1) + 1;
            strength_fwd[r       ][2] += 2;
        }
        // backward
        int l = max(-1, x[i] - sqrt_a);  // (l, x_i - 1]
        if (l < x[i] - 1) {
            strength_bck[l          + 1][0] -= a[i];
            strength_bck[(x[i] - 1) + 1][0] += a[i];
            strength_bck[l          + 1][0] += sq(x[i] - l - 1);
            strength_bck[l          + 1][1] += 2 * (x[i] - l - 1) + 1;
            strength_bck[l          + 1][2] += 2;
            strength_bck[(x[i] - 1) + 1][1] -= 1;
            strength_bck[(x[i] - 1) + 1][2] -= 2;
        }
    }
    // forward propagation
    REP (u, n) {
        REP (d, D - 1) strength_fwd[u][d] += strength_fwd[u][d + 1];
        REP (d, D) strength_fwd[u + 1][d] += strength_fwd[u][d];
        strength[u] += strength_fwd[u][0];
    }
    // backward propagation
    REP_R (u, n) {
        REP (d, D - 1) strength_bck[u + 1][d] += strength_bck[u + 1][d + 1];
        REP (d, D) strength_bck[u][d] += strength_bck[u + 1][d];
        strength[u] += strength_bck[u + 1][0];
    }
    // check
    if (n *(ll) m < 10000) {
        REP (u, n) {
            ll acc = 0;
            REP (i, m - 1) {
                acc += max(0ll, a[i] - sq(u - x[i]));
            }
            assert (strength[u] == acc);
        }
    }

    // find the unit to put the last shield
    vector<int> order(n);
    iota(ALL(order), 0);
    sort(ALL(order), [&](int u1, int u2) { return strength[u1] < strength[u2]; });
    auto get_min_strength = [&](int y) {  // at least O(N), but this is fast
        ll acc = LLONG_MAX;
        int bottleneck = -1;
        for (int u : order) {
            if (acc <= strength[u]) break;
            ll strength_u = strength[u] + max(0ll, a.back() - sq(u - y));
            if (strength_u < acc) {
                acc = strength_u;
                bottleneck = u;
            }
        }
        return make_pair(acc, bottleneck);
    };
    ll acc = LLONG_MIN;
    REP (u, n) {  // bruteforce for x_{m - 1}
        acc = max(acc, get_min_strength(u).first);
    }
    return acc;
}

int main() {
    while (true) {
        // input
        int n, m; cin >> n >> m;
        if (n == 0 and m == 0) break;
        vector<int> a(m), x(m - 1);
        REP (i, m - 1) {
            cin >> a[i] >> x[i];
            -- x[i];  // NOTE: this modifies the expr of strength
        }
        cin >> a[m - 1];

        // solve
        ll answer = solve(n, m, a, x);

        // output
        cout << answer << endl;
        cerr << answer << endl;
    }
    return 0;
}
```
