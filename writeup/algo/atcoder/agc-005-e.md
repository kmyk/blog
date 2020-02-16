---
layout: post
redirect_from:
  - /blog/2017/06/22/agc-005-e/
date: "2017-06-22T02:45:02+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "tree", "graph", "game" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc005/tasks/agc005_e" ]
---

# AtCoder Grand Contest 005: E - Sugigma: The Showdown

答え見たけどしばらくしていい感じに記憶が薄れた後に実装したのでまあはい。

## solution

追う側の青い辺による根付き木を中心に考える。$O(N)$。

追う側は常に(自分の木の上で)近付く方向に移動するとしてよい。そうでないなら逃げる側はパスすればよいため。
逃げる側の赤い辺$i - j$で青い木上の距離$d(i, j) \ge 3$なものがあれば、逃げる側は頂点$i, j$の上にいる状態で手番が回って来たら逃げ切りが確定する。
まとめると逃げ切りの判定は、頂点$Y$からの距離$t = d(Y, i)$が頂点$X$からの距離より真に小さい$t \lt d(X, i)$頂点$i$だけを通って逃げ切りができる頂点へ辿り着けるかどうかでよい。
これは$O(N)$。逃げ切れる頂点に辿り着けない場合は青い木の葉まで移動して捕まるのを待つことになるので、同様に移動できる頂点の中で$t = d(X, i)$が最大のものを覚えておき$2t$が答え。

## implementation

``` c++
#include <cstdio>
#include <stack>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

vector<int> compute_dist(int root, vector<vector<int> > const & g) {
    int n = g.size();
    vector<int> dist(n, -1);
    stack<int> stk;
    dist[root] = 0;
    stk.push(root);
    while (not stk.empty()) {
        int i = stk.top(); stk.pop();
        for (int j : g[i]) if (dist[j] == -1) {
            dist[j] = dist[i] + 1;
            stk.push(j);
        }
    }
    return dist;
}
vector<int> compute_parent(int root, vector<vector<int> > const & g) {
    int n = g.size();
    vector<int> parent(n, -1);
    stack<int> stk;
    stk.push(root);
    while (not stk.empty()) {
        int i = stk.top(); stk.pop();
        for (int j : g[i]) if (parent[j] == -1 and j != root) {
            parent[j] = i;
            stk.push(j);
        }
    }
    return parent;
}

int main() {
    // input
    int n, x, y; scanf("%d%d%d", &n, &x, &y); -- x; -- y;
    vector<vector<int> > g(n);
    repeat (i, n-1) {
        int a, b; scanf("%d%d", &a, &b); -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    vector<vector<int> > h(n);
    repeat (i, n-1) {
        int c, d; scanf("%d%d", &c, &d); -- c; -- d;
        h[c].push_back(d);
        h[d].push_back(c);
    }
    // solve
    vector<int> dist_h = compute_dist(y, h);
    vector<int> parent_h = compute_parent(y, h);
    vector<bool> escapable(n);
    repeat (i, n) for (int j : g[i]) {
        if (parent_h[i] != j
                and parent_h[j] != i
                and parent_h[i] != parent_h[j]
                and (parent_h[i] == -1 or parent_h[parent_h[i]] != j)
                and (parent_h[j] == -1 or parent_h[parent_h[j]] != i)) { // dist(i, j) >= 3
            escapable[i] = true;
            escapable[j] = true;
        }
    }
    int result = 0;
    vector<bool> used(n);
    stack<pair<int, int> > que;
    que.emplace(x, 0);
    while (not que.empty()) {
        int i, dist; tie(i, dist) = que.top(); que.pop();
        setmax(result, dist_h[i] * 2);
        if (escapable[i]) {
            result = -1;
            break;
        }
        for (int j : g[i]) if (not used[j]) {
            used[j] = true;
            if (dist_h[j] <= dist + 1) continue;
            que.emplace(j, dist + 1);
        }
    }
    // output
    printf("%d\n", result);
    return 0;
}
```
