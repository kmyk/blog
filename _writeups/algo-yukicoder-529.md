---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/529/
  - /blog/2017/06/10/yuki-529/
date: "2017-06-10T18:03:17+09:00"
tags: [ "competitive", "writeup", "yukicoder", "two-edge-connected-components-decomposition", "heavy-light-decomposition", "lowest-common-ancestor", "segment-tree" ]
"target_url": [ "http://yukicoder.me/problems/no/529" ]
---

# Yukicoder No.529 帰省ラッシュ

ライブラリ貼るだけというのは分かったが、肝心のライブラリがなかった。

## solution

二重辺連結成分分解 + 重軽分解 + segment木。$O(N + M + Q ((\log N)^2 + \log Q))$。

二重辺連結成分分解すると連結成分の木ができる。
元のグラフ上でpath $S - T$と移動するとき、この木の上の(一意な)path $S - T$上の成分の含む元のグラフの頂点は全て自由に通れ、それ以外の頂点は通過できない。
つまり連結成分の木の上のクエリだと見做してよい。

木の上の道に関するクエリなので、重軽分解してsegment木で処理できる。
segment木の葉には連結成分の番号$i$とその連結成分$i$中の頂点の持つ価値の最大値$w\_i$の対$(i, w\_i)$を持たせる。
演算は$w\_i$が大きい方を取る操作。
segment木とは別に、各連結成分$i$ごとにpriority queueを持たせ成分$i$中の価値の最大値$w\_i$を取り出せるようにしておく。

## implementation

合計で$343$行あるが、実質書いたのは下から$46$行だった。

``` c++
#include <algorithm>
#include <cassert>
#include <climits>
#include <cmath>
#include <cstdio>
#include <functional>
#include <queue>
#include <stack>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

/**
 * @brief 2-edge-connected components decomposition
 * @param g an adjacent list of the simple undirected graph
 * @note O(V + E)
 */
pair<int, vector<int> > decompose_to_two_edge_connected_components(vector<vector<int> > const & g) {
    int n = g.size();
    vector<int> imos(n); { // imos[i] == 0  iff  the edge i -> parent is a bridge
        vector<char> used(n); // 0: unused ; 1: exists on stack ; 2: removed from stack
        function<void (int, int)> go = [&](int i, int parent) {
            used[i] = 1;
            for (int j : g[i]) if (j != parent) {
                if (used[j] == 0) {
                    go(j, i);
                    imos[i] += imos[j];
                } else if (used[j] == 1) {
                    imos[i] += 1;
                    imos[j] -= 1;
                }
            }
            used[i] = 2;
        };
        repeat (i, n) if (used[i] == 0) {
            go(i, -1);
        }
    }
    int size = 0;
    vector<int> component_of(n, -1); {
        function<void (int)> go = [&](int i) {
            for (int j : g[i]) if (component_of[j] == -1) {
                component_of[j] = imos[j] == 0 ? size ++ : component_of[i];
                go(j);
            }
        };
        repeat (i, n) if (component_of[i] == -1) {
            component_of[i] = size ++;
            go(i);
        }
    }
    return { size, move(component_of) };
}
vector<vector<int> > decomposed_graph(int size, vector<int> const & component_of, vector<vector<int> > const & g) {
    int n = g.size();
    vector<vector<int> > h(size);
    repeat (i, n) for (int j : g[i]) {
        if (component_of[i] != component_of[j]) {
            h[component_of[i]].push_back(component_of[j]);
        }
    }
    repeat (k, size) {
        whole(sort, h[k]);
        h[k].erase(whole(unique, h[k]), h[k].end());
    }
    return h;
}

/**
 * @brief heavy light decomposition
 * @description for given rooted tree G = (V, E), decompose the vertices to disjoint paths, and construct new small rooted tree G' = (V', E') of the disjoint paths.
 * @see http://math314.hateblo.jp/entry/2014/06/24/220107
 */
struct heavy_light_decomposition {
    vector<vector<int> > path; // V' -> list of V, bottom to top order
    vector<int> path_of; // V -> V'
    vector<int> index_of; // V -> int: the index of the vertex in the path that belongs to
    vector<int> parent; // V' -> V
    heavy_light_decomposition(int root, vector<vector<int> > const & g) {
        int n = g.size();
        vector<int> tour_parent(n, -1);
        vector<int> euler_tour(n); {
            int i = 0;
            stack<int> stk;
            tour_parent[root] = -1;
            euler_tour[i ++] = root;
            stk.push(root);
            while (not stk.empty()) {
                int x = stk.top(); stk.pop();
                for (int y : g[x]) if (y != tour_parent[x]) {
                    tour_parent[y] = x;
                    euler_tour[i ++] = y;
                    stk.push(y);
                }
            }
        }
        path_of.resize(n);
        index_of.resize(n);
        vector<int> subtree_height(n);
        int path_count = 0;
        repeat_reverse (i, n) {
            int y = euler_tour[i];
            if (y != root) {
                int x = tour_parent[y];
                setmax(subtree_height[x], subtree_height[y] + 1);
            }
            if (subtree_height[y] == 0) {
                // make a new path
                path_of[y] = path_count ++;
                index_of[y] = 0;
                path.emplace_back();
                path.back().push_back(y);
                parent.push_back(tour_parent[y]);
            } else {
                // add to an existing path
                int i = -1;
                for (int z : g[y]) {
                    if (subtree_height[z] == subtree_height[y] - 1) {
                        i = path_of[z];
                        break;
                    }
                }
                assert (i != -1);
                path_of[y] = i;
                index_of[y] = path[i].size();
                path[i].push_back(y);
                parent[i] = tour_parent[y];
            }
        }
    }
};

/**
 * @brief lowest common ancestor with doubling
 */
struct lowest_common_ancestor {
    vector<vector<int> > a;
    vector<int> depth;
    lowest_common_ancestor() = default;
    /**
     * @note O(N \log N)
     * @param g an adjacent list of the tree
     */
    lowest_common_ancestor(int root, vector<vector<int> > const & g) {
        int n = g.size();
        int log_n = max<int>(1, ceil(log2(n)));
        a.resize(log_n, vector<int>(n, -1));
        depth.resize(n, -1);
        {
            auto & parent = a[0];
            stack<int> stk;
            depth[root] = 0;
            parent[root] = -1;
            stk.push(root);
            while (not stk.empty()) {
                int x = stk.top(); stk.pop();
                for (int y : g[x]) if (depth[y] == -1) {
                    depth[y] = depth[x] + 1;
                    parent[y] = x;
                    stk.push(y);
                }
            }
        }
        repeat (k, log_n-1) {
            repeat (i, n) {
                if (a[k][i] != -1) {
                    a[k+1][i] = a[k][a[k][i]];
                }
            }
        }
    }
    /**
     * @brief find the LCA of x and y
     * @note O(log N)
     */
    int operator () (int x, int y) const {
        int log_n = a.size();
        if (depth[x] < depth[y]) swap(x,y);
        repeat_reverse (k, log_n) {
            if (a[k][x] != -1 and depth[a[k][x]] >= depth[y]) {
                x = a[k][x];
            }
        }
        assert (depth[x] == depth[y]);
        assert (x != -1);
        if (x == y) return x;
        repeat_reverse (k, log_n) {
            if (a[k][x] != a[k][y]) {
                x = a[k][x];
                y = a[k][y];
            }
        }
        assert (x != y);
        assert (a[0][x] == a[0][y]);
        return a[0][x];
    }
    /**
     * @brief find the descendant of x for y
     */
    int descendant (int x, int y) const {
        assert (depth[x] < depth[y]);
        int log_n = a.size();
        repeat_reverse (k, log_n) {
            if (a[k][y] != -1 and depth[a[k][y]] >= depth[x]+1) {
                y = a[k][y];
            }
        }
        assert (a[0][y] == x);
        return y;
    }
};

template <typename SegmentTree>
struct heavy_light_decomposition_node_adapter {
    typedef typename SegmentTree::monoid_type CommutativeMonoid;
    typedef typename CommutativeMonoid::type underlying_type;

    vector<SegmentTree> segtree;
    heavy_light_decomposition & hl;
    lowest_common_ancestor & lca;
    CommutativeMonoid mon;
    heavy_light_decomposition_node_adapter(
            heavy_light_decomposition & a_hl,
            lowest_common_ancestor & a_lca,
            underlying_type initial_value = CommutativeMonoid().unit(),
            CommutativeMonoid const & a_mon = CommutativeMonoid())
            : hl(a_hl), lca(a_lca), mon(a_mon) {
        repeat (i, hl.path.size()) {
            segtree.emplace_back(hl.path[i].size(), initial_value, a_mon);
        }
    }

    void node_set(int x, underlying_type value) {
        int i = hl.path_of[x];
        int j = hl.index_of[x];
        segtree[i].point_set(j, value);
    }

    template <class Func>
    void path_do_something(int x, int y, Func func) {
        int z = lca(x, y);
        auto climb = [&](int & x) {
            while (hl.path_of[x] != hl.path_of[z]) {
                int i = hl.path_of[x];
                func(segtree[i], hl.index_of[x], hl.path[i].size());
                x = hl.parent[i];
            }
        };
        climb(x);
        climb(y);
        int i = hl.path_of[z];
        if (hl.index_of[x] > hl.index_of[y]) swap(x, y);
        func(segtree[i], hl.index_of[x], hl.index_of[y] + 1);
    }
    underlying_type path_concat(int x, int y) {
        underlying_type acc = mon.unit();
        path_do_something(x, y, [&](SegmentTree & segtree, int l, int r) {
            acc = mon.append(acc, segtree.range_concat(l, r));
        });
        return acc;
    }
};

template <class Monoid>
struct segment_tree {
    typedef Monoid monoid_type;
    typedef typename Monoid::type underlying_type;
    int n;
    vector<underlying_type> a;
    Monoid mon;
    segment_tree() = default;
    segment_tree(int a_n, underlying_type initial_value = Monoid().unit(), Monoid const & a_mon = Monoid()) : mon(a_mon) {
        n = 1; while (n < a_n) n *= 2;
        a.resize(2*n-1, mon.unit());
        fill(a.begin() + (n-1), a.begin() + (n-1 + a_n), initial_value); // set initial values
        repeat_reverse (i, n-1) a[i] = mon.append(a[2*i+1], a[2*i+2]); // propagate initial values
    }
    void point_set(int i, underlying_type z) { // 0-based
        a[i+n-1] = z;
        for (i = (i+n)/2; i > 0; i /= 2) { // 1-based
            a[i-1] = mon.append(a[2*i-1], a[2*i]);
        }
    }
    underlying_type range_concat(int l, int r) { // 0-based, [l, r)
        underlying_type lacc = mon.unit(), racc = mon.unit();
        for (l += n, r += n; l < r; l /= 2, r /= 2) { // 1-based loop, 2x faster than recursion
            if (l % 2 == 1) lacc = mon.append(lacc, a[(l ++) - 1]);
            if (r % 2 == 1) racc = mon.append(a[(-- r) - 1], racc);
        }
        return mon.append(lacc, racc);
    }
};

struct index_max_t {
    struct type { int index, value; };
    type unit() const { return { -1, INT_MIN }; }
    type append(type a, type b) { return a.value > b.value ? a : b; }
};
typedef index_max_t::type node_t;

int main() {
    int n, m, query; scanf("%d%d%d", &n, &m, &query);
    vector<vector<int> > g(n);
    repeat (i, m) {
        int a, b; scanf("%d%d", &a, &b); -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    int size; vector<int> component_of; tie(size, component_of) = decompose_to_two_edge_connected_components(g);
    vector<priority_queue<int> > que(size);
    vector<vector<int> > h = decomposed_graph(size, component_of, g);
    constexpr int root = 0;
    heavy_light_decomposition hl(root, h);
    lowest_common_ancestor lca(root, h);
    heavy_light_decomposition_node_adapter<segment_tree<index_max_t> > segtree(hl, lca);
    repeat (i, size) {
        segtree.node_set(i, (node_t) { i, -1 });
    }
    while (query --) {
        int type; scanf("%d", &type);
        if (type == 1) {
            int u, w; scanf("%d%d", &u, &w); -- u;
            int i = component_of[u];
            que[i].push(w);
            segtree.node_set(i, (node_t) { i, que[i].top() });
        } else if (type == 2) {
            int s, t; scanf("%d%d", &s, &t); -- s; -- t;
            auto result = segtree.path_concat(component_of[s], component_of[t]);
            int i = result.index;
            if (not que[i].empty()) {
                que[i].pop();
                int w = que[i].empty() ? -1 : que[i].top();
                segtree.node_set(i, (node_t) { i, w });
            }
            printf("%d\n", result.value);
        }
    }
    return 0;
}
```
