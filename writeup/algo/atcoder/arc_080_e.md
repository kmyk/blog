---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_080_e/
  - /writeup/algo/atcoder/arc-080-e/
  - /blog/2017/10/03/arc-080-e/
date: "2017-10-03T06:17:37+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "segment-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc080/tasks/arc080_c" ]
---

# AtCoder Regular Contest 080: E - Young Maids

editorialはOld Maidsになってるの何故。そもそもメイド要素どこ？

## solution

逆向きに考える。segment木とpriority queueでいい感じにして$O(N \log N)$。

最終的な$q$の$q\_0, q\_1$が最初の$p$の$p\_i, p\_j$だったとすると$i \lt j$であり、$[0, i), [i + 1, j), [j + 1, N)$の範囲をそれぞれ使い切った後に$p\_i, p\_j$を使うことから$i \equiv j - (i + 1) \equiv N - (j + 1) \equiv 0 \pmod{2}$でなければならない。
逆にこの条件を満たすような$p\_i, p\_j$は$q$の先頭に持っていける。

単純にはこれを再帰ですればよい。
$i, j$を探すのにはsegment木を使う。
$[0, i), [i + 1, j), [j + 1, N)$のそれぞれについて再帰し結果をmerge sortでまとめればよい。しかしこれでは$O(N^2)$かかり間に合わない。
そこでpriority queueを上手く使う。
$p\_i$とできる最小値を優先度として区間$[l, r)$をqueueに入れ、DFSだった再帰をBFSに直したような形で行えばよい。
これは$O(N \log N)$になるので間に合う。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <limits>
#include <queue>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;

template <class Monoid>
struct segment_tree {
    typedef Monoid monoid_type;
    typedef typename Monoid::underlying_type underlying_type;
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
template <typename T>
struct min_indexed_t {
    typedef pair<T, int> underlying_type;
    underlying_type unit() const { return make_pair(numeric_limits<T>::max(), -1); }
    underlying_type append(underlying_type a, underlying_type b) const { return min(a, b); }
};

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> p(n); repeat (i, n) scanf("%d", &p[i]);
    assert (n % 2 == 0);

    // solve
    segment_tree<min_indexed_t<int> > even(n), odd(n);
    repeat (i, n) {
        auto & segtree = (i % 2 == 0 ? even : odd);
        segtree.point_set(i, make_pair(p[i], i));
    }
    reversed_priority_queue<tuple<int, int, int> > que;
    auto push = [&](int l, int r) {
        if (l == r) return;
        auto & left  = (l % 2 == 0 ? even : odd);
        int x = left.range_concat(l, r - 1).first;
        que.emplace(x, l, r);
    };
    push(0, n);
    vector<int> result;
    while (not que.empty()) {
        int l, r; tie(ignore, l, r) = que.top(); que.pop();
        auto & left  = (l % 2 == 0 ? even : odd);
        auto & right = (l % 2 == 0 ? odd : even);
        int m1 = left.range_concat(l, r - 1).second;
        int m2 = right.range_concat(m1 + 1, r).second;
        result.push_back(p[m1]);
        result.push_back(p[m2]);
        push(l, m1);
        push(m1 + 1, m2);
        push(m2 + 1, r);
    }

    // output
    repeat (i, n) {
        printf("%d%c", result[i], i < n - 1 ? ' ' : '\n');
    }
    return 0;
}
```
