---
layout: post
redirect_from:
  - /blog/2016/09/07/hackerrank-camypapercon02-waiwai-otaku-panic/
date: "2016-09-07T00:49:30+09:00"
tags: [ "competitive", "writeup", "hackerrank", "camypapercon", "graph", "flow", "dag", "maximum-flow" ]
"target_url": [ "https://www.hackerrank.com/contests/camypapercon02/challenges/waiwai-otaku-panic" ]
---

# HackerRank Saiko~ No Contesuto #02: Waiwai Otaku Panic

## solution

DAGにして層別に最大流。ford fulkersonを使うと$O(NMA)$。

>   最短経路を通って

という制約により、目的地である頂点$1$からの距離が真に減少するような辺しか用いられない。
そのような辺だけ集めてくると明らかにDAGである。

>   同じ速度で途中で停止することなく

という制約により、車同士が衝突するならばそれらの出発地の目的地からの距離は全て同じである。
逆に言えば、目的地からの距離が異なる場所から出発する車同士は独立である。
よってそれぞれの距離に分けて考えればよい。
この準備のもとで、衝突性の判定は、それぞれの出発地からその車の量だけの最大流を流して、全て流れきるかどうかを見るだけになる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <queue>
#include <limits>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

struct edge_t { int to, cap, rev; };
int maximum_flow_destructive(int s, int t, vector<vector<edge_t> > & g) { // ford fulkerson, O(EF)
    int n = g.size();
    vector<bool> used(n);
    function<int (int, int)> dfs = [&](int i, int f) {
        if (i == t) return f;
        used[i] = true;
        for (edge_t & e : g[i]) {
            if (used[e.to] or e.cap <= 0) continue;
            int nf = dfs(e.to, min(f, e.cap));
            if (nf > 0) {
                e.cap -= nf;
                g[e.to][e.rev].cap += nf;
                return nf;
            }
        }
        return 0;
    };
    int result = 0;
    while (true) {
        used.clear(); used.resize(n);
        int f = dfs(s, numeric_limits<int>::max());
        if (f == 0) break;
        result += f;
    }
    return result;
}
void add_edge(vector<vector<edge_t> > & g, int from, int to, int cap) {
    g[from].push_back((edge_t) {   to, cap, int(g[  to].size()    ) });
    g[  to].push_back((edge_t) { from,   0, int(g[from].size() - 1) });
}
int maximum_flow(int s, int t, vector<vector<edge_t> > g /* adjacency list */) { // ford fulkerson, O(FE)
    return maximum_flow_destructive(s, t, g);
}

vector<int> dijkstra_simple_distance_from(int root, vector<vector<int> > const & g) {
    int n = g.size();
    vector<int> dist(n, -1);
    queue<int> que;
    dist[root] = 0;
    que.push(root);
    while (not que.empty()) {
        int i = que.front(); que.pop();
        for (int j : g[i]) if (dist[j] == -1) {
            dist[j] = dist[i] + 1;
            que.push(j);
        }
    }
    return dist;
}

int main() {
    // input
    int n, m; cin >> n >> m;
    vector<int> a(n); repeat (i,n-1) cin >> a[i+1];
    // prepare
    vector<vector<int> > g(n);
    repeat (i,m) {
        int f, t; cin >> f >> t; -- f; -- t;
        g[f].push_back(t);
        g[t].push_back(f);
    }
    const int src = n;
    const int dst = 0;
    vector<int> dist = dijkstra_simple_distance_from(dst, g);
    vector<vector<edge_t> > dag(n);
    repeat (i,n) for (int j : g[i]) {
        if (dist[j] < dist[i]) {
            add_edge(dag, i, j, 1);
        }
    }
    // compute
    bool ans = true;
    repeat (layer, n) {
        vector<vector<edge_t> > h = dag;
        h.emplace_back();
        int acc = 0;
        repeat (i,n) if (dist[i] == layer) {
            add_edge(h, src, i, a[i]);
            acc += a[i];
        }
        if (maximum_flow(src, dst, h) < acc) {
            ans = false;
            break;
        }
    }
    // output
    cout << (ans ? "NO PANIC" : "PANIC") << endl;
    return 0;
}
```
