---
layout: post
date: 2018-09-01T22:57:50+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc102/tasks/arc102_b" ]
---

# AtCoder Regular Contest 102: D - All Your Paths are Different Lengths

## 解法

$O(N)$。
$2$進数でやると$N \le 20$なので足りないが、$3$進数でやると上手く収まる。
辺重み$w \le 10^6$という制約に注意。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using namespace std;

constexpr int N = 20;
constexpr int MAX_L = 1000000;
constexpr int K = 13;
vector<tuple<int, int, int> > solve(int l) {
    vector<int> e(K + 1);
    e[0] = 1;
    REP (k, K) e[k + 1] = 3 * e[k];
    assert (e[K - 1] < MAX_L and MAX_L < e[K]);

    assert (l <= MAX_L);
    vector<int> trits;
    for (int acc = l; acc; acc /= 3) {
        trits.push_back(acc % 3);
    }

    vector<tuple<int, int, int> > edges;
    REP (k, (int)trits.size() - 1) {
        edges.emplace_back(N - k - 2, N - k - 1, 0);
        edges.emplace_back(N - k - 2, N - k - 1, e[k]);
        edges.emplace_back(N - k - 2, N - k - 1, 2 * e[k]);
    }
    int acc = 0;
    REP_R (k, trits.size()) {
        if (trits[k] == 1) {
            edges.emplace_back(0, N - k - 1, acc);
        } else if (trits[k] == 2) {
            edges.emplace_back(0, N - k - 1, acc);
            edges.emplace_back(0, N - k - 1, acc + e[k]);
        }
        acc += trits[k] * e[k];
    }

    array<bitset<MAX_L>, N> dp = {};
    dp[0][0] = true;
    REP (i, N - 1) {
        for (auto edge : edges) {
            int u, v, w; tie(u, v, w) = edge;
            if (u != i) continue;
            assert (dp[u].count() == (dp[u] << w).count());
            assert ((dp[v] & (dp[u] << w)).none());
            dp[v] |= dp[u] << w;
        }
    }
    assert (dp[N - 1].count() == l and (dp[N - 1] >> l).none());
    assert (edges.size() <= 60);
    return edges;
}

int main() {
    int l; cin >> l;
    auto edges = solve(l);
    cout << N << ' ' << edges.size() << endl;
    for (auto edge : edges) {
        int u, v, w; tie(u, v, w) = edge;
        cout << u + 1 << ' ' << v + 1 << ' ' << w << endl;
    }
    return 0;
}
```
