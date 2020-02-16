---
layout: post
date: 2018-12-15T06:00:00+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "duality", "linear-programming", "graph", "tree" ]
---

# TCO19 Single Round Match 744: Hard - CoverTreePaths

## 問題概要

根付き木 $$T$$ がありその頂点 $$i$$ にはそれぞれ必要数 $$d_i$$ と費用 $$d_i$$ が定められている。
それぞれの頂点 $$i$$ についてそれを使う回数を $$v_i \in \mathbb{N}$$ とする。
すべての頂点 $$i$$ についてそれ自身を含むその先祖の使用回数の和 $$\ge d_i$$ という条件の下で $$\sum v_i c_i$$ を最小化したい。
その最小値を求めよ。

## 解法

### 概要

線形計画問題として定式化して双対問題を見る。
すると貪欲に解ける。
計算量は曖昧だが $$O(N (\log N)^2)$$ ぐらいのはず。

### 詳細

線形計画問題として定式化すると

-   min: $$\mathbf{c}^t \mathbf{v}^t$$
-   sub. to: $$\sum _ {j \; \text{is an ancestor of} \; i} v_j \ge d_i$$ for all $$i$$
    -   つまり $$A \mathbf{v} \ge \mathbf{d}$$

その双対を取ると

-   max: $$\mathbf{d}^t \mathbf{u}^t$$
-   sub. to: $$\sum _ {j \; \text{is a descendant of} \; i} u_j \le c_i$$ for all $$i$$
    -   つまり $$A^t \mathbf{u} \le \mathbf{c}$$

となる。
「先祖すべての」が「子孫すべての」になったことにより木DPがやりやすくなる。

後は $$d_i$$ の順に貪欲にやることを考える。
各部分木について「その部分木のみを考えて解いたときの使われる $$d_i$$ の値の多重集合」を管理し、これを併合していけばよい。
これは $$c_i$$ の制約による制限を除いて貪欲に取ることになる。
単純な場合として直線状の木を考えるとよい。

## メモ

-   こういうので「双対」って言えるのかっこいいので覚えたい

## 実装

``` c++
#include <bits/stdc++.h>
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
typedef long long ll;
using namespace std;
class CoverTreePaths { public: long long minimumCost(int n, vector<int> p, vector<int> d, vector<int> c, vector<int> params); };

ll solve(int n, vector<int> parent, vector<int> const & d, vector<int> const & c) {
    // prepare the tree
    parent.push_back(-1);
    rotate(parent.begin(), parent.begin() + (n - 1), parent.end());
    vector<vector<int> > children(n);
    REP3 (i, 1, n) {
        children[parent[i]].push_back(i);
    }

    // solve the dual problem
    vector<map<int, ll, greater<int> > > dp(n);
    auto func = [&](int i) {
        auto & cur = dp[i];
        cur[d[i]] += c[i];
        for (int j : children[i]) {
            auto & prv = dp[j];
            if (cur.size() < prv.size()) {
                cur.swap(prv);
            }
            for (auto it : prv) {
                int d_i; ll u_i; tie(d_i, u_i) = it;
                cur[d_i] += u_i;
            }
            prv = map<int, ll, greater<int> >();
        }
        ll sum_u = 0;
        for (auto it : cur) {
            int d_i = it.first;
            if (c[i] < sum_u + cur[d_i]) {
                cur[d_i] = c[i] - sum_u;
            }
            sum_u += cur[d_i];
        }
        while (not cur.rbegin()->second) {
            cur.erase(prev(cur.end()));
        }
    };

    // to avoid stack overflow
    stack<pair<int, bool> > stk;
    stk.emplace(0, true);
    while (not stk.empty()) {
        int i; bool first; tie(i, first) = stk.top();
        stk.pop();
        if (not c[i]) continue;
        if (first) {
            stk.emplace(i, false);
            for (int j : children[i]) {
                stk.emplace(j, true);
            }
        } else {
            func(i);
        }
    }

    // the target function
    ll ans = 0;
    for (auto it : dp[0]) {
        int d_i; ll u_i; tie(d_i, u_i) = it;
        ans += d_i * u_i;
    }
    return ans;
}

long long CoverTreePaths::minimumCost(int n, vector<int> p, vector<int> d, vector<int> c, vector<int> params) {
    // load all input
    while (p.size() < n - 1) {
        p.push_back(((ll)params[0] * p.back() + params[1]) % (p.size() + 1));
    }
    while (d.size() < n) {
        d.push_back(1 + ((ll)params[2] * d.back() + params[3]) % params[4]);
    }
    while (c.size() < n) {
        c.push_back(1 + ((ll)params[5] * c.back() + params[6]) % params[7]);
    }
    // solve
    return solve(n, p, d, c);
}
```
