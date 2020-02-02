---
layout: post
alias: "/blog/2018/04/15/srm-733-medium/"
title: "TopCoder SRM 733 Medium. BuildingSpanningTreesDiv1"
date: "2018-04-15T02:35:10+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "graph", "matrix-tree-theorem", "matrix", "spanning-tree" ]
---

## problem

完全グラフが与えられ、その辺がいくつか指定される。指定された辺を全て使うような全域木の数はいくつか。

## solution

行列木定理。多重辺があっても動くと信じて出す。$O(N^3 + M\alpha(N))$。

想定解ではないようで雑に書くとTLEるはず。sampleに最大ケースがあるので確認してから提出。
想定解は[Cayley's formula](https://en.wikipedia.org/wiki/Cayley%27s_formula)の証明中の[Pr$\"u$fer sequence](https://en.wikipedia.org/wiki/Pr%C3%BCfer_sequence)を使ってどうこう。

## note

-   Laplacian行列の非対角成分は負なんだけど、これを忘れると最後のsampleだけ合わずに苦しむ
-   行列式求めるやつがライブラリにないと思って[ARC 018 D - 僕は友達が少ない](https://arc018.contest.atcoder.jp/tasks/arc018_4)の提出を引っ張ってきたのによく見たら既にあった

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
typedef long long ll;
using namespace std;
class BuildingSpanningTreesDiv1 { public: int getNumberOfSpanningTrees(int n, vector<int> x, vector<int> y); };

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

template <int32_t MOD>
struct mint {
    int64_t data;  // faster than int32_t a little
    mint() = default;  // data is not initialized
    mint(int64_t value) : data(value) {}  // assume value is in proper range
    inline mint<MOD> operator + (mint<MOD> other) const { int64_t c = this->data + other.data; return mint<MOD>(c >= MOD ? c - MOD : c); }
    inline mint<MOD> operator - (mint<MOD> other) const { int64_t c = this->data - other.data; return mint<MOD>(c <    0 ? c + MOD : c); }
    inline mint<MOD> operator * (mint<MOD> other) const { int64_t c = this->data * int64_t(other.data) % MOD; return mint<MOD>(c < 0 ? c + MOD : c); }
    inline mint<MOD> & operator += (mint<MOD> other) { this->data += other.data; if (this->data >= MOD) this->data -= MOD; return *this; }
    inline mint<MOD> & operator -= (mint<MOD> other) { this->data -= other.data; if (this->data <    0) this->data += MOD; return *this; }
    inline mint<MOD> & operator *= (mint<MOD> other) { this->data = this->data * int64_t(other.data) % MOD; if (this->data < 0) this->data += MOD; return *this; }
    inline mint<MOD> operator - () const { return mint<MOD>(this->data ? MOD - this->data : 0); }
    mint<MOD> pow(uint64_t k) const {
        mint<MOD> x = *this;
        mint<MOD> y = 1;
        for (uint64_t i = 1; i and (i <= k); i <<= 1) {
            if (k & i) y *= x;
            x *= x;
        }
        return y;
    }
    /**
     * @note MOD must be a prime
     */
    mint<MOD> inv() const {
        return pow(MOD - 2);
    }
    inline mint<MOD> operator /  (mint<MOD> other) const { return *this *  other.inv(); }
    inline mint<MOD> operator /= (mint<MOD> other) const { return *this *= other.inv(); }
    inline bool operator == (mint<MOD> other) const { return data == other.data; }
    inline bool operator != (mint<MOD> other) const { return data != other.data; }
};

template <class T>
T determinant(vector<vector<T> > const & original_a) {
    int n = original_a.size();
    auto a = original_a;
    T det = 1;
    REP (i, n) {
        REP (j, i) {
            if (a[j][j] == 0) {
                int k = j + 1;
                for (; k < n; ++ k) {
                    if (a[k][j] != 0) break;
                }
                if (k == n) return 0;
                REP3 (l, j, n) {
                    swap(a[j][l], a[k][l]);
                }
            }
            assert (a[j][j] != 0);
            T t = a[i][j] / a[j][j];
            REP3 (k, j + 1, n) {
                // a[i][k] -= a[j][k] * t;
                constexpr ll MOD = 987654323;
                a[i][k] = (a[i][k].data - a[j][k].data * t.data) % MOD;  // 2x faster
                if (a[i][k].data < 0) a[i][k].data += MOD;
            }
        }
    }
    REP (i, a.size()) det *= a[i][i];
    return det;
}

template <class T>
vector<vector<T> > small_matrix(vector<vector<T> > const & a) {
    int n = a.size();
    assert (n >= 1);
    auto b = a;
    b.resize(n - 1);
    REP (y, n - 1) {
        b[y].resize(n - 1);
    }
    return b;
}

constexpr ll MOD = 987654323;

int BuildingSpanningTreesDiv1::getNumberOfSpanningTrees(int n, vector<int> x, vector<int> y) {
    int m = x.size();

    // Prim
    union_find_tree uft(n);
    REP (i, m) {
        if (uft.is_same(x[i] - 1, y[i] - 1)) return 0;
        uft.unite_trees(x[i] - 1, y[i] - 1);
    }
    vector<int> root;
    REP (i, n) {
        if (uft.is_root(i)) {
            root.push_back(i);
        }
    }
    int k = root.size();

    // matrix-tree theorem
    vector<vector<mint<MOD> > >  a(k, vector<mint<MOD> >(k));
    REP (i, k) {
        int size_i = uft.tree_size(root[i]);
        REP (j, k) if (j != i) {
            int size_j = uft.tree_size(root[j]);
            a[i][j] = (MOD - size_i * size_j) % MOD;
            a[i][i] -= a[i][j];
        }
    }
    return determinant(small_matrix(a)).data;
}
```
