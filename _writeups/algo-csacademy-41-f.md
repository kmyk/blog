---
layout: post
redirect_from:
  - /writeup/algo/csacademy/41-f/
  - /writeup/algo/cs-academy/41-f/
  - /blog/2017/08/10/csa-41-f/
date: "2017-08-10T03:57:03+09:00"
tags: [ "competitive", "writeup", "csacademy", "binary-indexed-tree", "dp", "interval" ]
"target_url": [ "https://csacademy.com/contest/archive/task/subset-trees" ]
---

# CS Academy Round #41: F. Subset Trees

区間を右端でソートしていたため通せなかった。

## problem

閉区間が$N$個与えられる。
その部分集合に対し、区間を頂点とし端点含む交差がある区間どうしに辺を張りグラフを作る。
このグラフが木となるような部分集合はいくつあるか。

## solution

DP。
区間の集合を固定すれば各点で重複度のようなものを考えられて、これが$3$になってはいけない。
左から順に決めていくとして、区間の集合に対しその重複度が$2$な点と$1$な点で最も右のものそれぞれ$l, r$が考えられる。
$\mathrm{dp}(l, r)$をそのような区間の集合の数として求める。
$w = \max r\_i$として$O(w^2 \log w)$。

区間は左端でソートする。
右端だと$[1, 2], [3, 4], [2, 5]$みたいなケースでだめ。

愚直に書くと$O(w^3)$になるが、適当にやれば$O(w^2 \log w)$にできる。
ただしsegment treeを使うとTLEした。
binary indexed treeだと$2, 3$倍速くなって通る。
座圧しても回避できるはず。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

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

constexpr int mod = 1e9+7;
int main() {
    int n; scanf("%d", &n);
    vector<int> l(n), r(n); // [l, r]
    repeat (i, n) {
        scanf("%d%d", &l[i], &r[i]);
    }
    { // sort of SoA
        vector<pair<int, int> > lrs(n);
        repeat (i, n) {
            lrs[i] = { l[i], r[i] };
        }
        sort(whole(lrs));
        repeat (i, n) {
            tie(l[i], r[i]) = lrs[i];
        }
    }
    const int max_r = *max_element(whole(r));
    auto dp = vectors(max_r + 1, binary_indexed_tree<modplus_t<mod> >(max_r + 1));
    repeat (i, n) {
        repeat_from (r_j, l[i], max_r + 1) {
            dp[max(r[i], r_j)].point_append(min(r[i], r_j), dp[r_j].range_concat(0, l[i]));
        }
        dp[r[i]].point_append(0, 1);
    }
    ll result = 0;
    repeat (r_j, max_r + 1) {
        result += dp[r_j].range_concat(0, r_j + 1);
    }
    printf("%d\n", int(result % mod));
    return 0;
}
```

### 元々のDP

``` c++
    auto dp = vectors(max_r + 1, max_r + 1, ll());
    repeat (i, n) {
        repeat (l_j, l[i]) {
            repeat_from (r_j, l[i], max_r + 1) {
                dp[min(r[i], r_j)][max(r[i], r_j)] += dp[l_j][r_j];
            }
        }
        dp[0][r[i]] += 1;
    }
    ll result = 0;
    repeat (r_j, max_r + 1) {
        repeat (l_j, r_j + 1) {
            result += dp[l_j][r_j];
        }
    }
```
