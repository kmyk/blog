---
layout: post
date: 2018-08-12T03:39:04+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "graph", "tree-dp", "union-find-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc098/tasks/arc098_d" ]
---

# AtCoder Regular Contest 098: F - Donation

## solution

値が減るのは面倒なので逆からやって増えるようにする。
整理した結果としてグラフを分割する形がでるが、分割は面倒なのでunion-find木で逆からやる。
$A_i - B_i$の順で層に分けてKruskal法のような木DP。
$O(N \log N)$。

## note

editorialを見た。
ああ1000点問題だなあという感じであまりよく分かってない。
似た問が出たとき解けるかというと怪しい。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

struct union_find_tree {
    vector<int> data;
    union_find_tree() = default;
    explicit union_find_tree(size_t n) : data(n, -1) {}
    bool is_root(int i) { return data[i] < 0; }
    int find_root(int i) { return is_root(i) ? i : (data[i] = find_root(data[i])); }
    int tree_size(int i) { return - data[find_root(i)]; }
    int unite_trees(int i, int j) {
        i = find_root(i); j = find_root(j);
        if (i != j) {
            if (tree_size(i) < tree_size(j)) swap(i,j);
            data[i] += data[j];
            data[j] = i;
        }
        return i;
    }
    bool is_same(int i, int j) { return find_root(i) == find_root(j); }
};

ll solve(int n, int m, vector<ll> const & a, vector<ll> const & b, vector<vector<int> > const & g) {
    vector<ll> c(n);
    REP (i, n) {
        c[i] = max(a[i] - b[i], 0ll);
    }
    vector<int> order(n);
    iota(ALL(order), 0);
    sort(ALL(order), [&](int i, int j) { return c[i] < c[j]; });

    // tree-DP
    union_find_tree uft(n);
    vector<ll> dp(n, -1);
    vector<ll> sum_b = b;
    for (int i : order) {
        vector<int> roots;
        for (int j : g[i]) {
            j = uft.find_root(j);
            if (dp[j] != -1) {
                roots.push_back(j);
            }
        }
        sort(ALL(roots));
        roots.erase(unique(ALL(roots)), roots.end());
        for (int j : roots) {
            sum_b[i] += sum_b[j];
        }
        dp[i] = c[i] + sum_b[i];
        for (int j : roots) {
            chmin(dp[i], max(c[i], dp[j]) + sum_b[i] - sum_b[j]);
        }
        for (int j : roots) {
            uft.unite_trees(i, j);
        }
        int root = uft.find_root(i);
        dp[root] = dp[i];
        sum_b[root] = sum_b[i];
    }

    return dp[uft.find_root(0)];
}

int main() {
    // input
    int n, m; cin >> n >> m;
    vector<ll> a(n), b(n);
    REP (i, n) cin >> a[i] >> b[i];
    vector<vector<int> > g(n);
    REP (j, m) {
        int u, v; cin >> u >> v;
        -- u; -- v;
        g[u].push_back(v);
        g[v].push_back(u);
    }

    // solve
    ll w = solve(n, m, a, b, g);

    // output
    cout << w << endl;
    return 0;
}
```
