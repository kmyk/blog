---
layout: post
alias: "/blog/2017/12/29/utpc2011-l/"
title: "東京大学プログラミングコンテスト2011: L. L番目の数字"
date: "2017-12-29T07:48:37+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "aoj", "tree", "query", "coordinate-compression", "heavy-light-decomposition", "lowest-common-ancestor", "fully-indexable-dictionary", "wavelet-tree", "binary-search" ]
---

-   <http://www.utpc.jp/2011/problems/l_th.html>
-   <https://beta.atcoder.jp/contests/utpc2011/tasks/utpc2011_12>
-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2270>

## solution

Wavelet木 + 重軽分解 + 二分探索 + 座標圧縮。$O(N \log N + Q (\log N)^3)$。

木ではなく数列が固定され区間の中で$L$番目の数字を求めるクエリがたくさん与えられるのであれば、これはWavlet木を用いて$O(\log N)$で処理できる。
木上のクエリを列上のクエリに落とす手法として重軽分解があり、これを用いる。
ただし異なるWavlet木から得られた「区間中の$K$番目の数」という結果は上手く結合できない。
そこでWavelet木の別の機能で「区間中の$x$より小さい数の個数」を求め、これらを足し合わせた結果と$L$を比較して二分探索する。
しかしこれだと少し間に合わない。
Wavelet木や二分探索の計算量には扱う数の最大値$M$に対して$O(\log M)$が乗るが、これを事前に座標圧縮を用いて$M \le N$であるように落としておくと高速化され間に合う。
前処理に$O(N \log N)$、クエリに関しては二分探索 重軽分解 Wavelet木がそれぞれ$O(\log N)$要求して全体で$O((\log N)^3)$となる。

## implementation

``` c++
#include <algorithm>
#include <array>
#include <cassert>
#include <climits>
#include <cmath>
#include <cstdio>
#include <functional>
#include <map>
#include <numeric>
#include <stack>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

template <typename T>
map<T, int> coordinate_compression_map(vector<T> const & xs) {
    int n = xs.size();
    vector<int> ys(n);
    iota(ALL(ys), 0);
    sort(ALL(ys), [&](int i, int j) { return xs[i] < xs[j]; });
    map<T,int> f;
    for (int i : ys) {
        if (not f.count(xs[i])) { // make unique
            int j = f.size();
            f[xs[i]] = j; // f[xs[i]] has a side effect, increasing the f.size()
        }
    }
    return f;
}

template <typename T>
vector<int> apply_compression(map<T, int> const & f, vector<T> const & xs) {
    int n = xs.size();
    vector<int> ys(n);
    REP (i, n) ys[i] = f.at(xs[i]);
    return ys;
}

/**
 * @brief heavy light decomposition
 * @description for given rooted tree G = (V, E), decompose the vertices to disjoint paths, and construct new small rooted tree G' = (V', E') of the disjoint paths.
 * @see http://math314.hateblo.jp/entry/2014/06/24/220107
 */
struct heavy_light_decomposition {
    vector<vector<int> > path; // : V' -> list of V, bottom to top order
    vector<int> path_of; // : V -> V'
    vector<int> index_of; // : V -> int, the index of the vertex in the path that belongs to
    vector<int> parent; // : V' -> V, one node has -1 as the parent
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
        REP_R (i, n) {
            int y = euler_tour[i];
            if (y != root) {
                int x = tour_parent[y];
                chmax(subtree_height[x], subtree_height[y] + 1);
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

    /**
     * @brief reduce a path-query to range-queries aboud nodes
     * @arg lca is for the original tree, not the decomposed tree
     * @arg func is a callback function f(i, l, r), where i in V is an index of path, [l, r) is a range on the path
     */
    template <class LowestCommonAncestor, class Func>
    void path_node_do_something(LowestCommonAncestor const & lca, int x, int y, Func func) const {
        int z = lca(x, y);
        auto climb = [&](int & x) {
            while (path_of[x] != path_of[z]) {
                int i = path_of[x];
                func(i, index_of[x], path[i].size());
                x = parent[i];
            }
        };
        climb(x);
        climb(y);
        int i = path_of[z];
        if (index_of[x] > index_of[y]) swap(x, y);
        func(i, index_of[x], index_of[y] + 1);
    }
};

/**
 * @brief sparse table on a monoid
 * @note space: O(N log N)
 * @note time:  O(N log N) for construction; O(1) for query
 */
template <class Monoid>
struct sparse_table {
    typedef typename Monoid::underlying_type underlying_type;
    vector<vector<underlying_type> > table;
    Monoid mon;
    sparse_table() = default;
    sparse_table(vector<underlying_type> const & data, Monoid const & a_mon = Monoid())
            : mon(a_mon) {
        int n = data.size();
        int log_n = 32 - __builtin_clz(n);
        table.resize(log_n, vector<underlying_type>(n, mon.unit()));
        table[0] = data;
        for (int k = 0; k < log_n-1; ++ k) {
            for (int i = 0; i < n; ++ i) {
                table[k+1][i] = mon.append(table[k][i], i + (1ll<<k) < n ? table[k][i + (1ll<<k)] : mon.unit());
            }
        }
    }
    underlying_type range_concat(int l, int r) const {
        assert (0 <= l and l <= r and r <= table[0].size());
        if (l == r) return mon.unit();
        int k = 31 - __builtin_clz(r - l);  // log2
        return mon.append(table[k][l], table[k][r - (1ll<<k)]);
    }
};

struct indexed_min_monoid {
    typedef pair<int, int> underlying_type;
    underlying_type unit() const { return { INT_MAX, INT_MAX }; }
    underlying_type append(underlying_type a, underlying_type b) const { return min(a, b); }
};

/**
 * @brief lowest common ancestor with \pm 1 RMQ and sparse table
 * @see https://www.slideshare.net/yumainoue965/lca-and-rmq
 * @note verified http://www.utpc.jp/2011/problems/travel.html
 */
struct lowest_common_ancestor {
    sparse_table<indexed_min_monoid> table;
    vector<int> index;
    lowest_common_ancestor() = default;
    /**
     * @note O(N)
     * @param g is an adjacent list of a tree
     */
    lowest_common_ancestor(int root, vector<vector<int> > const & g) {
        vector<pair<int, int> > tour;
        index.assign(g.size(), -1);
        function<void (int, int, int)> go = [&](int i, int parent, int depth) {
            index[i] = tour.size();
            tour.emplace_back(depth, i);
            for (int j : g[i]) if (j != parent) {
                go(j, i, depth + 1);
                tour.emplace_back(depth, i);
            }
        };
        go(root, -1, 0);
        table = sparse_table<indexed_min_monoid>(tour);
    }
    /**
     * @note O(1)
     */
    int operator () (int x, int y) const {
        assert (0 <= x and x < index.size());
        assert (0 <= y and y < index.size());
        x = index[x];
        y = index[y];
        if (x > y) swap(x, y);
        return table.range_concat(x, y + 1).second;
    }
};

/**
 * @brief a fully indexable dictionary
 * @note space complexity o(N). 1.5N-bit consumed
 */
class fully_indexable_dictionary {
    static constexpr size_t block_size = 64;
    vector<uint64_t> block;
    vector<int32_t> rank_block;  // a blocked cumulative sum
public:
    size_t size;
    fully_indexable_dictionary() = default;
    template <typename T>
    fully_indexable_dictionary(vector<T> const & bits) {
        size = bits.size();
        size_t block_count = size / block_size + 1;
        block.resize(block_count);
        REP (i, size) if (bits[i]) {
            block[i / block_size] |= (1ull << (i % block_size));
        }
        rank_block.resize(block_count);
        rank_block[0] = 0;
        REP (i, block_count - 1) {
            rank_block[i + 1] = rank_block[i] + __builtin_popcountll(block[i]);
        }
    }
    /**
     * @brief count the number of value in [0, r)
     * @note O(1)
     */
    int rank(bool value, int r) const {
        assert (0 <= r and r <= size);
        uint64_t mask = (1ull << (r % block_size)) - 1;
        int rank_1 = rank_block[r / block_size] + __builtin_popcountll(block[r /block_size] & mask);
        return value ? rank_1 : r - rank_1;
    }
    int rank(bool value, int l, int r) const {
        assert (0 <= l and l <= r and r <= size);
        return rank(value, r) - rank(value, l);
    }
};

/**
 * @brief a wavelet matrix
 * @tparam BITS express the range [0, 2^BITS) of values. You can assume BITS \le \log N, using coordinate compression
 */
template <int BITS>
struct wavelet_matrix {
    static_assert (BITS < CHAR_BIT * sizeof(uint64_t), "");
    array<fully_indexable_dictionary, BITS> fid;
    array<int, BITS> zero_count;
    wavelet_matrix() = default;
    /**
     * @note O(N BITS)
     */
    template <typename T>
    wavelet_matrix(vector<T> data) {
        int size = data.size();
        REP (i, size) {
            assert (0 <= data[i] and data[i] < (1ull << BITS));
        }
        // bit-inversed radix sort
        vector<char> bits(size);
        vector<T> next(size);
        REP_R (k, BITS) {
            auto low  = next.begin();
            auto high = next.rbegin();
            REP (i, size) {
                bits[i] = bool(data[i] & (1ull << k));
                (bits[i] ? *(high ++) : *(low ++)) = data[i];
            }
            fid[k] = fully_indexable_dictionary(bits);
            zero_count[k] = low - next.begin();
            reverse(next.rbegin(), high);
            data.swap(next);
        }
    }
    /**
     * @brief count the number of values in [value_l, value_r) in range [l, r)
     * @note O(BITS)
     */
    int range_frequency(int l, int r, uint64_t value_l, uint64_t value_r) const {
        assert (0 <= l and l <= r and r <= fid[0].size);
        assert (0 <= value_l and value_l <= value_r and value_r <= (1ull << BITS));
        return range_frequency(BITS - 1, l, r, 0, value_l, value_r);
    }
    int range_frequency(int k, int l, int r, uint64_t v, uint64_t a, uint64_t b) const {
        if (l == r) return 0;
        if (k == -1) return (a <= v and v < b) ? r - l : 0;
        uint64_t nv  =  v |  (1ull << k);
        uint64_t nnv = nv | ((1ull << k) - 1);
        if (nnv < a or b <= v) return 0;
        if (a <= v and nnv < b) return r - l;
        int lc = fid[k].rank(1, l);
        int rc = fid[k].rank(1, r);
        return
            range_frequency(k - 1,             l - lc,             r - rc,  v, a, b) +
            range_frequency(k - 1, lc + zero_count[k], rc + zero_count[k], nv, a, b);
    }
};

/**
 * @brie a flexible binary search
 * @param[in] p  a monotone predicate defined on [l, r)
 * @return  \min \{ x \in [l, r) \mid p(x) \}, or r if it doesn't exist
 */
template <typename UnaryPredicate>
ll binsearch(ll l, ll r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        ll m = (l + r) / 2;
        (p(m) ? r : l) = m;
    }
    return r;
}

int main() {
    // input
    int n, queries; scanf("%d%d", &n, &queries);
    vector<int> x(n); REP (i, n) scanf("%d", &x[i]);
    vector<vector<int> > g(n);
    REP (i, n - 1) {
        int a, b; scanf("%d%d", &a, &b);
        -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    // prepare
    // // coordinate compression
    auto uncompress = x;
    sort(ALL(uncompress));
    uncompress.erase(unique(ALL(uncompress)), uncompress.end());
    x = apply_compression(coordinate_compression_map(x), x);
    // // heavy light decomposition
    constexpr int root = 0;
    heavy_light_decomposition hl(root, g);
    lowest_common_ancestor lca(root, g);
    // // wavelet matrix
    assert (n < (1 << 17));
    vector<wavelet_matrix<17> > wm;
    for (auto const & path : hl.path) {
        vector<int> y;
        for (int i : path) {
            y.push_back(x[i]);
        }
        wm.emplace_back(y);
    }
    // serve
    while (queries --) {
        int v, w, l; scanf("%d%d%d", &v, &w, &l);
        -- v; -- w; -- l;
        // binary search
        auto pred = [&](int value) {
            int cnt = 0;
            hl.path_node_do_something(lca, v, w, [&](int i, int il, int ir) {
                cnt += wm[i].range_frequency(il, ir, 0, value + 1);
            });
            return cnt > l;
        };
        int result = uncompress[binsearch(0, n, pred)];
        printf("%d\n", result);
    }
    return 0;
}
```
