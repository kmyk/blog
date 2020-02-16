---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-068-e/
  - /blog/2017/05/16/arc-068-e/
date: "2017-05-16T21:32:40+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "binary-indexed-tree", "segment-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc068/tasks/arc068_c" ]
---

# AtCoder Regular Contest 068: E - Snuke Line

## solution

区間$[l, r)$に累積和で足し込んで幅$d$で飛ばしながら舐めるのはすぐに思い付くが、同じ区間を複数回数えてしまってだめ。
しかしそのような事態が起こるのは$d \le r - l$のときだけなので、幅$d$で舐めるときには$r - l \lt d$な区間のみの累積和にできれば解決する。
$d \le r - l$な区間は明らかに踏むので別に数えればよい。
これは$d$を$1$から増やしながら、それに伴なって区間を追加していけばよい。
これはbinary indexed treeがあれば、$O(N + M \log M)$。
篩ほど速くはないが調和級数の和のオーダーは$O(\log n)$である。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <numeric>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;

template <class Monoid>
struct segment_tree {
    typedef typename Monoid::type T;
    int n;
    vector<T> a;
    Monoid mon;
    segment_tree() = default;
    segment_tree(int a_n, Monoid const & a_mon = Monoid()) : mon(a_mon) {
        n = 1; while (n < a_n) n *= 2;
        a.resize(2*n-1, mon.unit);
    }
    void point_update(int i, T z) { // 0-based
        a[i+n-1] = z;
        for (i = (i+n)/2; i > 0; i /= 2) {
            a[i-1] = mon.append(a[2*i-1], a[2*i]);
        }
    }
    T range_concat(int l, int r) { // 0-based, [l, r)
        T lacc = mon.unit, racc = mon.unit;
        for (l += n, r += n; l < r; l /= 2, r /= 2) { // loop, 2x faster than recursion
            if (l % 2 == 1) lacc = mon.append(lacc, a[(l ++) - 1]);
            if (r % 2 == 1) racc = mon.append(a[(-- r) - 1], racc);
        }
        return mon.append(lacc, racc);
    }
};
struct plus_t {
    typedef int type;
    const int unit = 0;
    int append(int a, int b) { return a + b; }
};

int main() {
    int n, m; scanf("%d%d", &n, &m);
    vector<int> l(n), r(n); repeat (i,n) { scanf("%d%d", &l[i], &r[i]); ++ r[i]; }
    vector<int> length_order(n);
    whole(iota, length_order, 0);
    whole(sort, length_order, [&](int i, int j) { return r[i] - l[i] < r[j] - l[j]; });
    vector<int> result(m+1);
    segment_tree<plus_t> segtree(m+2); // or a binary indexed tree
    int i = 0;
    repeat_from (d,1,m+1) {
        result[d] += n - i;
        for (int x = 0; x <= m; x += d) {
            result[d] += segtree.range_concat(0, x+1);
        }
        for (; i < n and r[length_order[i]] - l[length_order[i]] <= d; ++ i) {
            int li = l[length_order[i]];
            int ri = r[length_order[i]];
            segtree.point_update(li, segtree.range_concat(li, li+1) + 1);
            segtree.point_update(ri, segtree.range_concat(ri, ri+1) - 1);
        }
    }
    repeat_from (d,1,m+1) {
        printf("%d\n", result[d]);
    }
    return 0;
}
```
