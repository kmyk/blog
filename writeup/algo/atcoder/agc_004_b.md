---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-004-b/
  - /blog/2017/09/05/agc-004-b/
date: "2017-09-05T17:22:45+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc004/tasks/agc004_b" ]
---

# AtCoder Grand Contest 004: B - Colorful Slimes

誤読していた。
変色の際に元の色のスライムも残るのだと思っていた。
この条件だと$O(N^3)$までしか落とせなかったが、両端繋がってないことにすると$O(N^2)$なはず。
元の問題だと両端繋がってないことにしても$O(N)$にはならない気がするのでちょっと面白い。

## solution

魔法を唱える回数$k$を総当たり。最終的な色$i$のスライムがどの色のスライムとして捕まえられるべきかは$\min \\{ a\_j \mid i - k \le j \le i \\}$を使って求まる。$O(N)$。

## implementation

sparse tableである必要はない。

``` c++
#include <cassert>
#include <climits>
#include <cmath>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

template <class Monoid>
struct sparse_table {
    typedef typename Monoid::underlying_type underlying_type;
    vector<vector<underlying_type> > table;
    Monoid mon;
    sparse_table() = default;
    sparse_table(vector<underlying_type> const & data, Monoid const & a_mon = Monoid())
            : mon(a_mon) {
        int n = data.size();
        int log_n = log2(n) + 1;
        table.resize(log_n, vector<underlying_type>(n, mon.unit()));
        table[0] = data;
        for (int k = 0; k < log_n-1; ++ k) {
            for (int i = 0; i < n; ++ i) {
                table[k+1][i] = mon.append(table[k][i], i + (1ll<<k) < n ? table[k][i + (1ll<<k)] : mon.unit());
            }
        }
    }
    underlying_type range_concat(int l, int r) const {
        if (l == r) return range_concat(0, table[0].size());
        if (l > r) return mon.append(
                l == table[0].size() ? mon.unit() : range_concat(l, table[0].size()),
                r == 0 ? mon.unit() : range_concat(0, r));
        assert (0 <= l and l <= r and r <= table[0].size());
        if (l == r) return mon.unit();
        int k = log2(r - l);
        return mon.append(table[k][l], table[k][r - (1ll<<k)]);
    }
};
struct min_t {
    typedef int underlying_type;
    int unit() const { return INT_MAX; }
    int append(int a, int b) const { return min(a, b); }
};

constexpr ll inf = ll(1e18)+9;
int main() {
    // input
    int n, x; scanf("%d%d", &n, &x);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    // solve
    sparse_table<min_t> rmq(a);
    ll result = inf;
    repeat (k, n) {
        ll acc = x *(ll) k;
        repeat (i, n) {
            acc += rmq.range_concat(i, (i + k + 1) % n);
        }
        setmin(result, acc);
    }
    // output
    printf("%lld\n", result);
    return 0;
}
```
