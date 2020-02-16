---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-015-e/
  - /blog/2017/07/31/agc-015-e/
date: "2017-07-31T11:51:50+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "dp", "binary-indexed-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc015/tasks/agc015_e" ]
---

# AtCoder Grand Contest 015: E - Mr.Aoki Incubator

## 反省

直前に同様に区間と被覆に落とす問題を解いたのに思い付けなかった。
座標ばかりに注目して速度の区間というのが出てこなかった。
頭がほしい。

## solution

[editorial](https://atcoder.jp/img/agc015/editorial.pdf)を見て。
ただしDPを$O(N^2)$から$O(N)$にする部分はbinary indexed treeとかsegment treeとかを使った方が楽。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <map>
#include <numeric>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;

template <typename Monoid>
struct binary_indexed_tree { // on monoid
    typedef typename Monoid::underlying_type underlying_type;
    vector<underlying_type> data;
    Monoid mon;
    binary_indexed_tree(size_t n, Monoid const & a_mon = Monoid()) : mon(a_mon) {
        data.resize(n, mon.unit());
    }
    void point_append(size_t i, underlying_type z) { // data[i] += z
        for (size_t j = i + 1; j <= data.size(); j += j & -j) data[j - 1] = mon.append(data[j - 1], z);
    }
    underlying_type initial_range_concat(size_t i) { // sum [0, i)
        underlying_type acc = mon.unit();
        for (size_t j = i; 0 < j; j -= j & -j) acc = mon.append(data[j - 1], acc);
        return acc;
    }
    underlying_type range_concat(size_t l, size_t r) {
        return mon.append(initial_range_concat(r), mon.invert(initial_range_concat(l)));
    }
};
template <int mod>
struct modplus_t {
    typedef int underlying_type;
    int unit() const { return 0; }
    int append(int a, int b) const { int c = a + b; return c < mod ? c : c - mod; }
    int invert(int a) const { return a ? mod - a : 0; }
};

template <typename T>
map<T,int> coordinate_compression_map(vector<T> const & xs) {
    int n = xs.size();
    vector<int> ys(n);
    whole(iota, ys, 0);
    whole(sort, ys, [&](int i, int j) { return xs[i] < xs[j]; });
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
vector<int> apply_compression(map<T,int> const & f, vector<T> const & xs) {
    int n = xs.size();
    vector<int> ys(n);
    repeat (i,n) ys[i] = f.at(xs[i]);
    return ys;
}
void sort_with_pair(int n, vector<int> & a, vector<int> & b) {
    vector<pair<int, int> > c(n);
    repeat (i, n) {
        c[i] = { a[i], b[i] };
    }
    whole(sort, c);
    repeat (i, n) {
        tie(a[i], b[i]) = c[i];
    }
}

constexpr int mod = 1e9+7;
int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> x(n), v(n); repeat (i, n) scanf("%d%d", &x[i], &v[i]);
    x = apply_compression(coordinate_compression_map(x), x);
    v = apply_compression(coordinate_compression_map(v), v);
    // solve
    sort_with_pair(n, x, v);
    vector<int> l(n); // [l, r)
    l[n - 1] = v[n - 1];
    repeat_reverse (i, n - 1) {
        l[i] = min(l[i + 1], v[i]);
    }
    vector<int> r(n);
    r[0] = v[0] + 1;
    repeat (i, n - 1) {
        r[i + 1] = max(r[i], v[i + 1] + 1);
    }
    binary_indexed_tree<modplus_t<mod> > dp(n + 1);
    dp.point_append(0, 1);
    repeat (i, n) {
        dp.point_append(r[i], dp.range_concat(l[i], r[i] + 1));
    }
    // output
    printf("%d\n", dp.range_concat(n, n + 1));
    return 0;
}
```
