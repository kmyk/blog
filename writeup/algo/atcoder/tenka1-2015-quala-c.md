---
layout: post
alias: "/blog/2016/01/18/tenka1-2015-quala-c/"
title: "天下一プログラマーコンテスト2015予選A C - 天下一美術館"
date: 2016-01-18T20:46:37+09:00
tags: [ "competitive", "writeup", "atcoder", "tenka1-programmer-contest", "graph", "flow", "maximum-flow", "ford-fulkerson", "bipartite-graph", "maximum-matching" ]
---

フロー精進中。

## [C - 天下一美術館](https://beta.atcoder.jp/contests/tenka1-2015-quala/tasks/tenka1_2015_qualA_c) {#c}

### 解法

2マス同時に新規に一致させられるような交換の数を数えればよい。
これで一致させられなかったマスに関しては、全て個別に色を反転させる他ない。

交換の数は2部グラフの最大マッチングとして計算できる。
白マスと黒マスで交換すべきものに関して辺を張る。同じ色のマスを交換することはないため2部グラフとなる。このグラフの最大マッチングは交換の数になる。
なお、実装の際にdinicを使うとtleする。

[AtCoder Regular Contest 013 D - 切り分けできるかな？](/kimiyuki.net/blog/2016/01/16/arc-013-d/)にかなり似ている。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <limits>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
struct edge_t { int to, cap, rev; };
void add_edge(vector<vector<edge_t> > & g, int from, int to, int cap) {
    g[from].push_back((edge_t){ to, cap, int(g[to].size()) });
    g[to].push_back((edge_t){ from, 0, int(g[from].size())-1 });
}
int maximum_flow(int s, int t, vector<vector<edge_t> > g /* adjacency list */) { // ford fulkerson, O(FE)
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
const int dy[] = { -1, 1, 0, 0 };
const int dx[] = { 0, 0, 1, -1 };
int main() {
    int h, w; cin >> h >> w;
    array<vector<vector<bool> >,2> p;
    repeat (i,2) {
        p[i].resize(h, vector<bool>(w));
        repeat (y,h) repeat (x,w) {
            int t; cin >> t; p[i][y][x] = t;
        }
    }
    vector<vector<edge_t> > g(2*h*w+2);
    int a = 0, b = h*w, s = 2*h*w, t = 2*h*w+1;
    repeat (y,h) repeat (x,w) {
        add_edge(g, s, a+y*w+x, 1);
        add_edge(g, b+y*w+x, t, 1);
        if (not p[0][y][x] and p[1][y][x]) {
            repeat (k,4) {
                int ny = y + dy[k];
                int nx = x + dx[k];
                if (ny < 0 or h <= ny or nx < 0 or w <= nx) continue;
                if (p[0][ny][nx] and not p[1][ny][nx]) {
                    add_edge(g, a+y*w+x, b+ny*w+nx, 1);
                }
            }
        }
    }
    int total = 0; repeat (y,h) repeat (x,w) if (p[0][y][x] != p[1][y][x]) ++ total;
    cout << total - maximum_flow(s,t,g) << endl;
    return 0;
}
```
