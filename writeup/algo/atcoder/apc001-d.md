---
layout: post
date: 2018-07-10T07:47:01+09:00
tags: [ "competitive", "writeup", "atcoder", "apc", "graph", "connected-components", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/apc001/tasks/apc001_d" ]
---

# AtCoder Petrozavodsk Contest 001: D - Forest

## solution

とりあえず可能性判定のみ考える (典型)。
大きさ$1$の連結成分同士を直接繋いでしまうと詰むことから、反対に、その時点で$1$番目と$2$番目に大きい連結成分を繋ぐことを繰り返すのが最適。
これを踏まえ次にコストについて。各連結成分について最低ひとつの頂点は使う必要があるが、それ以外は自由である。
よってそのような貪欲でよい。
sortがボトルネックで$O(N \log N)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

ll solve(int n, int m, vector<int> a, vector<vector<int> > const & g) {
    // decompose to connected components
    vector<vector<int> > forest; {
        vector<bool> used(n);
        function<void (int)> go = [&](int i) {
            used[i] = true;
            forest.back().push_back(i);
            for (int j : g[i]) if (not used[j]) {
                go(j);
            }
        };
        REP (i, n) if (not used[i]) {
            forest.emplace_back();
            go(i);
        }
    }
    if (forest.size() == 1) return 0;

    // check the possibility
    vector<int> size;
    for (auto && tree : forest) {
        size.push_back(tree.size());
    }
    sort(ALL(size));
    while (size.size() >= 2) {
        int it = size.back();
        size.pop_back();
        if (it == 0) return -1;
        if (size.back() == 0) return -1;
        size.back() += it - 2;
    }

    // compute the cost
    ll acc = 0;
    vector<int> indices;
    for (auto && tree : forest) {
        int i = *min_element(ALL(tree), [&](int i, int j) { return a[i] < a[j]; });
        acc += a[i];
        a[i] = INT_MAX;  // remove it
    }
    sort(ALL(a));
    int k = forest.size() - 2;
    acc += accumulate(a.begin(), a.begin() + k, 0ll);
    return acc;
}

int main() {
    // input
    int n, m; cin >> n >> m;
    vector<int> a(n);
    REP (i, n) cin >> a[i];
    vector<vector<int> > g(n);
    REP (i, m) {
        int x, y; cin >> x >> y;
        g[x].push_back(y);
        g[y].push_back(x);
    }

    // solve
    ll answer = solve(n, m, a, g);

    // output
    if (answer == -1) {
        cout << "Impossible" << endl;
    } else {
        cout << answer << endl;
    }
    return 0;
}
```
