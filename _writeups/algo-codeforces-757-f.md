---
layout: post
redirect_from:
  - /writeup/algo/codeforces/757-f/
  - /blog/2017/03/22/cf-757-f/
date: "2017-03-22T19:06:32+09:00"
tags: [ "competitive", "writeup", "codeforces", "dominator-tree" ]
"target_url": [ "http://codeforces.com/contest/757/problem/F" ]
---

# Codecraft-17 and Codeforces Round #391 (Div. 1 + Div. 2, combined): F - Team Rocket Rises Again

大変疲れた。実装に苦労したわりになんとなくしか理解できてないのがつらい。
普通の用途にはboostのdominator tree使うべきですね。

## problem

連結とは限らない無向グラフ$G$と頂点$s \in G'$が与えられる。
$G'$の$s$を含む連結成分を$G$とする。
$G$の各頂点$v \in G$に対し$s$からの最短距離を$d(v)$とする。
$G$からある頂点$w \ne s$とその接続辺を除去したグラフ$G \setminus \\{ w \\}$上でも同様に関数$d_w(v)$を定める。
ただし$w$を含む到達不能な頂点$v$に対する値は$\infty$とする。
$\max \\{ \\#\\{ v \in G \mid d(v) \ne d_w(v) \\} \mid w \ne s \\}$を答えよ。

## solution

dominator treeを構築しその真部分木の大きさの最大のものを答える。準線形時間。

dominator treeの実装には[Dominator Tree - sigma425のブログ](http://sigma425.hatenablog.com/entry/2015/12/25/224053)を見て。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <numeric>
#include <queue>
#include <tuple>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
constexpr ll inf = ll(1e18)+9;

// http://sigma425.hatenablog.com/entry/2015/12/25/224053
vector<int> dominator_tree(vector<vector<int> > const & g, int root_g) { // G is a digraph which any vertex can be reached from the root
    int n = g.size();
    vector<vector<int> > invert_g(n);
    repeat (i,n) for (int j : g[i]) invert_g[j].push_back(i);
    // 1. make dfs tree
    vector<int> to_rank(n, -1); // index on original digraph G -> index on dfs-tree T
    vector<int> from_rank(n);
    vector<int> parent(n, -1); // on dfs-tree T, indexed on G
    { // init
        int next_rank = 0;
        function<void (int)> dfs = [&](int i) {
            to_rank[i] = next_rank;
            from_rank[next_rank] = i;
            ++ next_rank;
            for (int j : g[i]) if (to_rank[j] == -1) {
                parent[j] = i;
                dfs(j);
            }
        };
        dfs(root_g);
    }
    // x. check connectivity
    repeat (i,n) assert (to_rank[i] != -1); // or disconnected graph
    // 2. compute sdom
    vector<int> sdom(n);
    repeat (i,n) sdom[i] = to_rank[i];
    vector<int> foo(n, -1); // vertex, used in 3.
    // 2.1. union-find tree
    vector<int> root(n); whole(iota, root, 0);
    vector<int> min_sdom_index(n); whole(iota, min_sdom_index, 0); // data on union-find tree
    function<int (int)> find = [&](int i) {
        if (root[i] == i) return i;
        int j = find(root[i]);
        if (sdom[min_sdom_index[root[i]]] < sdom[min_sdom_index[i]]) {
            min_sdom_index[i] = min_sdom_index[root[i]];
        }
        return root[i] = j;
    };
    auto link = [&](int i, int j) {
        assert (root[j] == j);
        root[j] = i;
    };
    vector<vector<int> > bucket(n);
    for (int rank_i = n-1; rank_i >= 1; -- rank_i) {
        // 2.2. compute sdom
        int i = from_rank[rank_i];
        for (int j : invert_g[i]) {
            // int rank_j = to_rank[j];
            // if (rank_j < rank_i) { // up
            //     setmin(sdom[i], rank_j);
            // }
            find(j);
            setmin(sdom[i], sdom[min_sdom_index[j]]);
        }
        // 2.3. compute foo
        bucket[from_rank[sdom[i]]].push_back(i);
        for (int j : bucket[parent[i]]) {
            find(j);
            foo[j] = min_sdom_index[j];
        }
        bucket[parent[i]] = vector<int>(); // clear
        // 2.4. link
        link(parent[i], i);
    }
    // 3. compute idom
    vector<int> idom(n);
    repeat_from (rank_i,1,n) {
        int i = from_rank[rank_i];
        int j = foo[i];
        idom[i] = (sdom[i] == sdom[j] ? sdom : idom)[j];
    }
    vector<int> result(n);
    repeat (i,n) if (i != root_g) {
        result[i] = from_rank[idom[i]];
    }
    result[root_g] = -1;
    return result;
}

int main() {
    // input
    int n, m, start; scanf("%d%d%d", &n, &m, &start); -- start;
    assert (2 <= n and n <= 200000);
    assert (1 <= m and m <= min<ll>(n*ll(n-1)/2, 300000));
    assert (0 <= start and start < n);
    vector<vector<pair<int, ll> > > g(n);
    repeat (i,m) {
        int u, v, w; scanf("%d%d%d", &u, &v, &w); -- u; -- v;
        assert (0 <= u and u < n);
        assert (0 <= v and u < n);
        assert (1 <= w and w <= 1000000000);
        g[u].emplace_back(v, w);
        g[v].emplace_back(u, w);
    }
    // compute distance
    vector<ll> dist(n, inf); {
        vector<bool> used(n);
        priority_queue<pair<ll, int> > que;
        dist[start] = 0;
        que.emplace(- dist[start], start);
        while (not que.empty()) {
            int i = que.top().second; que.pop();
            if (used[i]) continue;
            used[i] = true;
            for (auto it : g[i]) {
                int j; ll cost; tie(j, cost) = it;
                if (dist[i] + cost >= dist[j]) continue;
                dist[j] = dist[i] + cost;
                que.emplace(- dist[j], j);
            }
        }
    }
    // make connective
    repeat (i,n) if (dist[i] == inf) {
        g[start].emplace_back(i, inf);
    }
    // make the digraph with edges for shortest paths
    vector<vector<int> > h(n);
    repeat (i,n) {
        for (auto it : g[i]) {
            int j; ll cost; tie(j, cost) = it;
            if (dist[i] + cost == dist[j]) {
                h[i].push_back(j);
            }
        }
    }
    // dominate it
    vector<int> idom = dominator_tree(h, start);
    // compute subtree sizes
    vector<vector<int> > t(n);
    repeat (i,n) if (i != start) t[idom[i]].push_back(i);
    vector<int> size(n); {
        function<int (int, int)> dfs = [&](int i, int parent) {
            for (int j : t[i]) {
                size[i] += dfs(j, i);
            }
            return size[i] += 1;
        };
        dfs(start, -1);
    }
    // make result
    repeat (i,n) if (dist[i] == inf) {
        size[i] = 0;
    }
    size[start] = 0;
    int result = *whole(max_element, size);
    // output
    printf("%d\n", result);
    return 0;
}
```
