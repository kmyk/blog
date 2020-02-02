---
layout: post
title: "AtCoder Petrozavodsk Contest 001: F - XOR Tree"
date: 2018-07-27T03:19:07+09:00
tags: [ "competitive", "writeup", "atcoder", "apc", "graph", "xor", "bit-dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/apc001/tasks/apc001_f" ]
---

## note

木DP部分は自然にやればできたが、bit DPだけなぜか忘れていて気付けなかった (editorialを見た)。

## solution

木DP。bit DP。$A = \max a_i$として$O(N A + 3^A A)$。

まず重みが辺に乗っているのが面倒。
そこで根をひとつ勝手に固定し、頂点に移してしまう。
そして $\mathrm{dp} : (\text{subtrees}) \to 2^{15}$ の形の木DPをする。
各部分木について、その部分木内から外へ出ていくような単純pathについての値$x$への操作があるかを求めていく。
複数の子から同じ値$x$のpathsが出てきたらこれを繋げて消し、それ以外では消さずすべて上へ持ち上げて最後に根の部分でbit DPして処理する。
xorなのでいい感じにやれば上手く行く。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

int solve(int n, const vector<int> & x, const vector<int> & y, const vector<int> & a) {
    constexpr int MAX_A = 0xf;
    assert (*max_element(ALL(a)) <= MAX_A);

    // make the adjacent list
    vector<vector<int> > g(n);
    REP (i, n - 1) {
        g[x[i]].push_back(y[i]);
        g[y[i]].push_back(x[i]);
    }

    // fix a root
    vector<int> parent(n, -1);
    constexpr int root = 0; {
        function<void (int)> go = [&](int i) {
            for (int j : g[i]) if (j != parent[i]) {
                parent[j] = i;
                go(j);
            }
        };
        go(root);
    }

    // move labels to nodes
    vector<int> b(n, -1);
    REP (i, n - 1) {
        if (parent[x[i]] == y[i]) {
            b[x[i]] = a[i];
        } else if (x[i] == parent[y[i]]) {
            b[y[i]] = a[i];
        } else {
            assert (false);
        }
    }

    // tree dp
    int removed = 0;
    function<int (int)> go = [&](int i) {
        int cnt1 = 0;
        for (int j : g[i]) if (j != parent[i]) {
            int cnt2 = go(j);
            REP (x, MAX_A + 1) if (cnt2 & (1 << x)) {
                removed += (bool)(cnt1 & (1 << x));
                cnt1 ^= 1 << x;
            }
        }
        int k = b[i];
        if (k != -1) {
            REP (x, MAX_A + 1) if (cnt1 & (1 << x)) {
                k ^= x;
            }
            if (k != 0) {
                removed += (bool)(cnt1 & (1 << k));
                cnt1 ^= 1 << k;
            }
        }
        return cnt1;
    };
    int cnt = go(root);

    // finialize
    constexpr int INF = 1e9 + 7;
    vector<int> dp(1 << (MAX_A + 1), INF);
    dp[0] = 0;
    REP (s, 1 << (MAX_A + 1)) if ((s | cnt) == cnt) {
        for (int t = 0; t != s; t = (t - s) & s) {  // t is a proper subset of s
            if (__builtin_popcount(s ^ t) == 1) {
                chmin(dp[s], dp[t] + 1);
            } else {
                int acc = 0;
                REP (x, MAX_A + 1) if ((s ^ t) & (1 << x)) {
                    acc ^= x;
                }
                if (acc == 0) {
                    chmin(dp[s], dp[t] + __builtin_popcount(s ^ t) - 1);
                }
            }
        }
    }
    return removed + dp[cnt];
}

int main() {
    // input
    int n; cin >> n;
    vector<int> x(n - 1), y(n - 1), a(n - 1);
    REP (i, n - 1) {
        cin >> x[i] >> y[i] >> a[i];
    }

    // solve
    int answer = solve(n, x, y, a);

    // output
    cout << answer << endl;
    return 0;
}
```
