---
layout: post
title: "CODE FESTIVAL 2018 Final: I - Homework"
date: 2018-11-22T23:26:48+09:00
tags: [ "competitive", "writeup", "atcoder", "code-festival", "binary-search", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2018-final/tasks/code_festival_2018_final_i" ]
---

## 解法

### 概要

答え $$X$$ を二分探索。
$$X$$ のbitを小さい側から見ながら貪欲。
計算量は $$O((\log \sum 2^{A_i}) \cdot N \log N)$$。

### 詳細

答え $$X$$ が既知としたとき、次のようにすればよい:

1.  $$X$$ の1bit目が1なら $$A_i = 1$$ であるような宿題 $$i$$ のなかで $$B_i$$ を最大にするものを使う
1.  $$A_i = 1$$ であるような宿題 $$i$$ でまだ使われてないものを $$B_i$$ の順で貪欲にふたつずつ組にし $$A_k = 2, \; B_k = B_i + B_j$$ のようにして $$A_k = 2$$ の宿題であったことにする
1.  $$X$$ の2bit目が1なら $$A_i = 2$$ であるような宿題 $$i$$ のなかで $$B_i$$ を最大にするものを使う
1.  $$A_i = 2$$ であるような宿題 $$i$$ でまだ使われてないものを $$B_i$$ の順で貪欲にふたつずつ組にし $$A_k = 3, \; B_k = B_i + B_j$$ のようにして $$A_k = 3$$ の宿題であったことにする
1.  $$X$$ の2bit目が3なら $$A_i = 2$$ であるような宿題 $$i$$ のなかで $$B_i$$ を最大にするものを使う
1.  $$\dots$$

この貪欲が最適なのは明らか。
単純に見ると長さ $$N$$ の列に対するソートなどの操作を $$L = \log \sum 2^{A_i} \le 60$$ 回行なうことになる。
しかし長さは毎回半分になることから $$L$$ 回の長さの合計は $$2N$$ を越えず、$$X$$ を固定するごとに $$O(L + N \log N)$$ で済む。
$$L \lt N$$ と仮定すると全体の計算量は $$O(L N \log N)$$。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

template <typename UnaryPredicate>
int64_t binsearch(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;
        (p(m) ? r : l) = m;
    }
    return r;
}

constexpr int L = 60;
ll solve(int n, ll k, vector<int> const & a, vector<ll> const & b) {
    vector<vector<ll> > f(L);
    REP (i, n) {
        f[a[i]].push_back(b[i]);
    }
    REP (i, L) {
        sort(ALL(f[i]));
    }
    return binsearch(0, 1ll << L, [&](ll sum_a) {
        ll sum_b = 0;
        vector<ll> cur, prv;
        REP (i, L) {
            cur.insert(cur.end(), ALL(f[i]));
            if (cur.empty()) continue;
            sort(ALL(cur));
            if (sum_a & (1ll << i)) {
                sum_b += cur.back();
                cur.pop_back();
            }
            cur.swap(prv);
            cur.clear();
            while (not prv.empty()) {
                int k = prv.size();
                if (k == 1) {
                    cur.push_back(prv[k - 1]);
                    prv.pop_back();
                } else {
                    cur.push_back(prv[k - 1] + prv[k - 2]);
                    prv.pop_back();
                    prv.pop_back();
                }
            }
        }
        return k <= sum_b;
    });
}

int main() {
    int n; ll k; cin >> n >> k;
    vector<int> a(n);
    vector<ll> b(n);
    REP (i, n) cin >> a[i] >> b[i];
    cout << solve(n, k, a, b) << endl;
    return 0;
}
```
