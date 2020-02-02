---
layout: post
title: "Google Code Jam Kickstart Round G 2018: B. Combining Classes"
date: 2018-10-25T15:47:36+09:00
tags: [ "competitive", "writeup", "gcj", "kickstart", "imos", "segment-tree" ]
"target_url": [ "https://codejam.withgoogle.com/codejam/contest/5374486/dashboard#s=p1" ]
---

## 問題

$N$個の区間$[L_i, R_i) \subseteq \mathbb{N}$が与えられる。
これらの区間中の要素をすべてまとめて整列したとき、$K_i$番目に大きい要素を$S_i$とする。
$Q$個の質問$K_1, \dots, K_Q$が与えられるので$\sum i S_i$を答えよ。

## 解法

### 概要

各自然数$n \in \mathbb{N}$に対し、それ以上の要素の数を前処理で数えておく。
見るべきは高々$2N + Q$点だが、要素の最大値は$10^9$程度なので適当に誤魔化すと楽。
前処理は動的構築遅延伝搬segment木に線形操作monoid、あるいは線形関数をimos法で処理してもできる。
$O(N + Q + M_1 + M_2 + M_3)$。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T, class U> inline void chmax(T & a, U const & b) { a = max<T>(a, b); }

struct linear_function_t {
    ll a, b;
};
linear_function_t operator + (linear_function_t f, linear_function_t g) {
    return (linear_function_t) { f.a + g.a, f.b + g.b };
}
ll apply(linear_function_t f, ll x) {
    return f.a * x + f.b;
}

ll solve1(int n, int q, vector<int> const & l, vector<int> const & r, vector<int> const & k) {
    vector<pair<int, linear_function_t> > imos;
    REP (i, n) {
        imos.emplace_back(l[i], (linear_function_t) {  1, - l[i] });
        imos.emplace_back(r[i], (linear_function_t) { -1,   r[i] });
    }
    sort(ALL(imos), [&](auto p, auto q) { return p.first > q.first; });

    vector<int> order(q);
    iota(ALL(order), 0);
    sort(ALL(order), [&](int i, int j) { return k[i] < k[j]; });

    ll answer = 0;
    linear_function_t f = { 0, 0 };
    auto imos_it = imos.begin();
    auto order_it = order.begin();
    for (int s = *max_element(ALL(r)); s > 0 and order_it != order.end(); ) {
        while (imos_it != imos.end() and imos_it->first >= s) {
            f = f + imos_it->second;
            ++ imos_it;
        }
        while (order_it != order.end() and k[*order_it] < apply(f, s)) {
            answer += s * (*order_it + 1ll);
            ++ order_it;
        }
        int next_s = 0;
        if (imos_it != imos.end()) {
            chmax(next_s, imos_it->first);
        }
        if (order_it != order.end()) {
            int k_i = k[*order_it];
            for (int delta = 1 << 30; ; delta >>= 1) {
                if (k_i >= apply(f, next_s - delta) or delta == 1) {
                    chmax(next_s, s - delta);
                    break;
                }
            }
        }
        s = next_s;
    }
    return answer;
}

ll solve(int n, int q, array<int, 3> const & a, array<int, 3> const & b, array<int, 3> const & c, array<int, 3> const & m, vector<int> x, vector<int> y, vector<int> z) {
    auto generate = [&](int k, int len, vector<int> & w) {
        w.resize(len);
        REP3 (i, 2, len) {
            w[i] = ((ll)a[k] * w[i - 1] % m[k] + (ll)b[k] * w[i - 2] % m[k] + c[k]) % m[k];
        }
    };
    generate(0, n, x);
    generate(1, n, y);
    generate(2, q, z);
    vector<int> l(n), r(n);
    REP (i, n) {
        tie(l[i], r[i]) = minmax({ x[i], y[i] });
        l[i] += 1;
        r[i] += 2;
    }
    return solve1(n, q, l, r, z);
}

int main() {
    int testcase; cin >> testcase;
    REP (caseindex, testcase) {
        int n, q; cin >> n >> q;
        array<int, 3> a, b, c, m;
        vector<int> x(2), y(2), z(2);
        cin >> x[0] >> x[1] >> a[0] >> b[0] >> c[0] >> m[0];
        cin >> y[0] >> y[1] >> a[1] >> b[1] >> c[1] >> m[1];
        cin >> z[0] >> z[1] >> a[2] >> b[2] >> c[2] >> m[2];
        ll answer = solve(n, q, a, b, c, m, x, y, z);
        cerr << "Case #" << caseindex + 1 << ": " << answer << endl;
        cout << "Case #" << caseindex + 1 << ": " << answer << endl;
    }
    return 0;
}
```
