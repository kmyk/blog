---
layout: post
redirect_from:
  - /writeup/algo/aoj/1275/
  - /blog/2017/07/28/aoj-1275/
date: "2017-07-28T20:47:27+09:00"
tags: [ "competitive", "writeup", "aoj", "icpc", "icpc-asia", "binary-indexed-tree", "binary-search" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1275" ]
---

# AOJ 1275. And Then There Was One

なんだか有名な問題らしいしそうでなくても愚直$O(N^2)$で通るらしい。
テストケース数$T = 100$が乗るからだめかなと思ったが、$N \le 10000$から減るだけなのでcache乗りが良いとか小さいケースが混ざってるとかで間に合うというのも分かる。
なんでA問題なのにこんなに難しいんだと言ってたらこれだよ。

## solution

binary indexed tree + 二分探索。いくつ進めばいいかを毎回求める。$\Delta$進めると仮定して現在の位置$i$からの区間$[i, i + \Delta]$に使用済みの点がちょうど$\Delta - k$個あればよい。$O(n (\log n)^2)$

残ってる点の数$n'$に対し$k \ge n'$になってしまったときは余りを取る操作が必要。丁寧にどうぞ。

## implementation

``` c++
#include <cassert>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

template <typename Group>
struct binary_indexed_tree { // on group
    typedef typename Group::underlying_type underlying_type;
    vector<underlying_type> data;
    Group mon;
    binary_indexed_tree(size_t n, Group const & a_mon = Group()) : mon(a_mon) {
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

struct plus_t {
    typedef int underlying_type;
    int unit() const { return 0; }
    int append(int a, int b) const { return a + b; }
    int invert(int a) const { return - a; }
};

template <typename UnaryPredicate>
ll binsearch(ll l, ll r, UnaryPredicate p) { // [l, r), p is monotone
    assert (l < r);
    -- l;
    while (r - l > 1) {
        ll m = (l + r) / 2;
        (p(m) ? r : l) = m;
    }
    return r; // = min { x in [l, r) | p(x) }, or r
}

int main() {
    while (true) {
        int n, k, m; scanf("%d%d%d", &n, &k, &m);
        if (n == 0 and k == 0 and m == 0) break;
        -- m;
        binary_indexed_tree<plus_t> bit(n);
        repeat (i, n - 1) {
            bit.point_append(m, 1);
            int delta = binsearch(1, n, [&](int d) {
                int used = bit.range_concat(m, min(n, m + d + 1)) + (n < m + d + 1 ? bit.range_concat(0, m + d + 1 - n) : 0);
                return (k - 1) % (n - i - 1) + 1 <= (d + 1 - used);
            });
            m = (m + delta) % n;
        }
        printf("%d\n", m + 1);
    }
    return 0;
}
```
