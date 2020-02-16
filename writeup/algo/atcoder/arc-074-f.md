---
layout: post
alias: "/blog/2017/05/20/arc-074-f/"
date: "2017-05-20T22:32:41+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "minimum-cut", "maximum-flow", "ford-fulkerson" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc074/tasks/arc074_d" ]
---

# AtCoder Regular Contest 074: F - Lotus Leaves

無向グラフに流すときって単に両向きに張るだけでいいんだっけ？コストは両方同じ$1$でいいのか？とか言ってた。

## solution

行と列を頂点、蓮の葉を辺として無向グラフを作り、最小カットを求める。
Ford-Fulkerson法で$E \le HW$かつ$F \le H + W$なので$O(HW (H + W))$。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

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

int main() {
    // input
    int h, w; scanf("%d%d", &h, &w);
    int inf = h*w;
    vector<vector<char> > f = vectors(h, w, char());
    repeat (y,h) repeat (x,w) scanf(" %c", &f[y][x]);
    // maximum flow
    const int src = 0;
    const int dst = 1;
    auto node_y = [&](int y) { return 2 + y; };
    auto node_x = [&](int x) { return 2 + h + x; };
    vector<vector<edge_t> > g(2 + h + w);
    repeat (y,h) repeat (x,w) {
        if (f[y][x] == 'S') {
            add_edge(g, src, node_y(y), inf);
            add_edge(g, src, node_x(x), inf);
        } else if (f[y][x] == 'T') {
            add_edge(g, node_y(y), dst, inf);
            add_edge(g, node_x(x), dst, inf);
        }
        if (f[y][x] != '.') {
            add_edge(g, node_y(y), node_x(x), 1);
            add_edge(g, node_x(x), node_y(y), 1);
        }
    }
    int flow = maximum_flow_destructive(src, dst, g);
    // output
    if (flow >= inf) flow = -1;
    printf("%d\n", flow);
    return 0;
}
```
