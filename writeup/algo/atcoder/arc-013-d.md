---
layout: post
alias: "/blog/2016/01/16/arc-013-d/"
title: "AtCoder Regular Contest 013 D - 切り分けできるかな？"
date: 2016-01-16T17:39:18+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "graph", "flow", "bipartite-graph", "maximum-matching", "maximum-flow" ]
---

## [D - 切り分けできるかな？](https://beta.atcoder.jp/contests/arc013/tasks/arc013_4) {#d}

### 解法

1回の切断でその結果の分銅を両方利用できるような切断を行える回数が分かれば答えが求まる。
作製可能な分銅ひとつに付きふたつ頂点を用意し、切断を辺とするような二部グラフを作る。
このグラフの最大マッチングの大きさは、結果の両方を利用できる切断の回数になるので、これを計算すればよい。

### 実装

edmonds karpで投げたらtleしたのでdinicを書いた。流量が少ないのでford furkersonでもよかった。

``` c++
#include <iostream>
#include <vector>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
ll maximum_flow(int s, int t, vector<vector<ll> > const & capacity /* adjacency matrix */) { // dinic, O(V^2E)
    int n = capacity.size();
    vector<vector<ll> > flow(n, vector<ll>(n));
    auto residue = [&](int i, int j) { return capacity[i][j] - flow[i][j]; };
    vector<vector<int> > g(n); repeat (i,n) repeat (j,n) if (capacity[i][j] or capacity[j][i]) g[i].push_back(j); // adjacency list
    ll result = 0;
    while (true) {
        vector<int> level(n, -1); level[s] = 0;
        queue<int> q; q.push(s);
        for (int d = n; not q.empty() and level[q.front()] < d; ) {
            int i = q.front(); q.pop();
            if (i == t) d = level[i];
            for (int j : g[i]) if (level[j] == -1 and residue(i,j) > 0) {
                level[j] = level[i] + 1;
                q.push(j);
            }
        }
        vector<bool> finished(n);
        function<ll (int, ll)> augmenting_path = [&](int i, ll cur) -> ll {
            if (i == t or cur == 0) return cur;
            if (finished[i]) return 0;
            finished[i] = true;
            for (int j : g[i]) if (level[i] < level[j]) {
                ll f = augmenting_path(j, min(cur, residue(i,j)));
                if (f > 0) {
                    flow[i][j] += f;
                    flow[j][i] -= f;
                    finished[i] = false;
                    return f;
                }
            }
            return 0;
        };
        bool cont = false;
        while (true) {
            ll f = augmenting_path(s, numeric_limits<ll>::max());
            if (f == 0) break;
            result += f;
            cont = true;
        }
        if (not cont) break;
    }
    return result;
}
const ll INF = 1000000007;
int main() {
    set<pair<int,int> > e;
    int n; cin >> n;
    repeat (i,n) {
        ll x, y, z; cin >> x >> y >> z;
        repeat_from (j,1,x) { ll k = x-j; e.emplace(j*y*z,k*y*z); e.emplace(k*y*z,j*y*z); }
        repeat_from (j,1,y) { ll k = y-j; e.emplace(x*j*z,x*k*z); e.emplace(x*k*z,x*j*z); }
        repeat_from (j,1,z) { ll k = z-j; e.emplace(x*y*j,x*y*k); e.emplace(x*y*k,x*y*j); }
    }
    map<ll,int> v; for (auto it : e) if (not v.count(it.first)) { int i = v.size(); v[it.first] = i; }
    vector<vector<ll> > g(2*v.size()+2, vector<ll>(2*v.size()+2));
    int s = 2*v.size(), t = 2*v.size()+1;
    for (auto it : v) {
        int va = it.second;
        g[s][va] = 1;
        g[v.size() + va][t] = 1;
    }
    for (auto it : e) {
        ll a, b; tie(a,b) = it;
        g[v[a]][v.size() + v[b]] = INF;
    }
    cout << 2*v.size() - maximum_flow(s,t,g) << endl;
    return 0;
}
```
