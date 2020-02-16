---
layout: post
alias: "/blog/2017/07/02/icpc-2017-domestic-practice-f/"
date: "2017-07-02T23:30:08+09:00"
tags: [ "competitive", "writeup", "aoj", "icpc-domestic", "minimum-cost-flow", "dag" ]
---

# ACM-ICPC 2017 模擬国内予選: F. マトリョーシカ

[解説](http://acm-icpc.aitea.net/index.php?2017%2FPractice%2F%E6%A8%A1%E6%93%AC%E5%9B%BD%E5%86%85%E4%BA%88%E9%81%B8%2F%E8%AC%9B%E8%A9%95)を見た。面倒なのでライブラリもコピペ。負辺もいける最小費用流ライブラリは便利。

## solution

丸ごと流せる。重み付き頂点path被覆に帰着させて最小費用流。$V = F = N, \; E = N^2$とおいて$O(F E \log V)$。

1.  まず体積のことを無視すると、頂点path被覆になる
    -   これは二部matchingに帰着させて解ける
    -   二部matchingは最大流で解ける
2.  ここに重みを載せる
    -   重み最大二部matching
    -   これは最小費用流: 重みを負で載せて、必ず$F$流せるように適当に辺を張る
        -   $\mathrm{source} \to $\mathrm{sink}$の費用$0$の辺を張るのが単純
        -   あるいは各マトリョーシカで$\mathrm{i} \to $\mathrm{i}$の費用$0$の辺を張るとsourceからの到達不能点が消えるため楽かも

## implementation

``` c++
#include <algorithm>
#include <array>
#include <cstdio>
#include <queue>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;

template <class T>
struct edge_t { int to; T cap, cost; int rev; };
template <class T>
void add_edge(vector<vector<edge_t<T> > > & graph, int from, int to, T cap, T cost) {
    graph[from].push_back((edge_t<T>) {   to, cap,  cost, int(graph[  to].size())     });
    graph[  to].push_back((edge_t<T>) { from,  0, - cost, int(graph[from].size()) - 1 });
}
/**
 * @brief minimum-cost flow with primal-dual method
 * @note mainly O(V^2UC) for U is the sum of capacities and C is the sum of costs. and additional O(VE) if negative edges exist
 */
template <class T>
T min_cost_flow_destructive(int src, int dst, T flow, vector<vector<edge_t<T> > > & graph) {
    T result = 0;
    vector<T> potential(graph.size());
    if (0 < flow) { // initialize potential when negative edges exist (slow). you can remove this if unnecessary
        whole(fill, potential, numeric_limits<T>::max());
        potential[src] = 0;
        while (true) { // Bellman-Ford algorithm
            bool updated = false;
            repeat (e_from, graph.size()) for (auto & e : graph[e_from]) if (e.cap) {
                if (potential[e_from] == numeric_limits<T>::max()) continue;
                if (potential[e.to] > potential[e_from] + e.cost) {
                    potential[e.to] = potential[e_from] + e.cost; // min
                    updated = true;
                }
            }
            if (not updated) break;
        }
    }
    while (0 < flow) {
        // update potential using dijkstra
        vector<T> distance(graph.size(), numeric_limits<T>::max()); // minimum distance
        vector<int> prev_v(graph.size()); // constitute a single-linked-list represents the flow-path
        vector<int> prev_e(graph.size());
        { // initialize distance and prev_{v,e}
            reversed_priority_queue<pair<T, int> > que; // distance * vertex
            distance[src] = 0;
            que.emplace(0, src);
            while (not que.empty()) { // Dijkstra's algorithm
                T d; int v; tie(d, v) = que.top(); que.pop();
                if (potential[v] == numeric_limits<T>::max()) continue;
                if (distance[v] < d) continue;
                // look round the vertex
                repeat (e_index, graph[v].size()) {
                    // consider updating
                    edge_t<T> e = graph[v][e_index];
                    int w = e.to;
                    if (potential[w] == numeric_limits<T>::max()) continue;
                    T d1 = distance[v] + e.cost + potential[v] - potential[w]; // updated distance
                    if (0 < e.cap and d1 < distance[e.to]) {
                        distance[w] = d1;
                        prev_v[w] = v;
                        prev_e[w] = e_index;
                        que.emplace(d1, w);
                    }
                }
            }
        }
        if (distance[dst] == numeric_limits<T>::max()) return -1; // no such flow
        repeat (v, graph.size()) {
            if (potential[v] == numeric_limits<T>::max()) continue;
            potential[v] += distance[v];
        }
        // finish updating the potential
        // let flow on the src->dst minimum path
        T delta = flow; // capacity of the path
        for (int v = dst; v != src; v = prev_v[v]) {
            setmin(delta, graph[prev_v[v]][prev_e[v]].cap);
        }
        flow -= delta;
        result += delta * potential[dst];
        for (int v = dst; v != src; v = prev_v[v]) {
            edge_t<T> & e = graph[prev_v[v]][prev_e[v]]; // reference
            e.cap -= delta;
            graph[v][e.rev].cap += delta;
        }
    }
    return result;
}

int main() {
    while (true) {
        int n; scanf("%d", &n);
        if (n == 0) break;
        vector<array<int, 3> > size(n);
        repeat (i, n) {
            repeat (j, 3) {
                scanf("%d", &size[i][j]);
            }
            whole(sort, size[i]);
        }
        auto volume = [&](int i) { return size[i][0] * size[i][1] * size[i][2]; };
        int total_volume = 0;
        vector<vector<edge_t<int> > > g(2 * n + 2);
        const int src = 2 * n;
        const int dst = 2 * n + 1;
        repeat (i, n) {
            add_edge(g, src, i, 1, 0);
            repeat (j, n) {
                if (    size[i][0] > size[j][0] and
                        size[i][1] > size[j][1] and
                        size[i][2] > size[j][2]) {
                    add_edge(g, i, n + j, 1, - volume(j));
                }
            }
            add_edge(g, n + i, dst, 1, 0);
            total_volume += volume(i);
        }
        add_edge(g, src, dst, n, 0);
        int result = total_volume + min_cost_flow_destructive(src, dst, n, g);
        printf("%d\n", result);
    }
    return 0;
}
```
