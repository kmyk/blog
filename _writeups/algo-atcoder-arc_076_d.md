---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_076_d/
  - /writeup/algo/atcoder/arc-076-d/
  - /blog/2017/12/31/arc-076-d/
date: "2017-12-31T20:37:16+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "minimum-spanning-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc076/tasks/arc076_b" ]
---

# AtCoder Regular Contest 076: D - Built?

## solution

最小全域木を作ればよい。${}\_NC\_2$個の可能な道を全て列挙すると間に合わないが、距離の定義を見れば$x$座標$y$座標でsortして隣合う点の間にだけ辺を張れば十分であることが分かる。$O(N \log N)$。

入れる距離がChebyshev距離($\min$でなくて$\max$)でもだいたい同様にできる気がする。
Euclid距離だと無理矢理やるかkd木ということになる。

## implementation

Kruskal法。

``` c++
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <numeric>
#include <queue>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;

struct disjoint_sets {
    vector<int> data;
    disjoint_sets() = default;
    explicit disjoint_sets(size_t n) : data(n, -1) {}
    bool is_root(int i) { return data[i] < 0; }
    int find_root(int i) { return is_root(i) ? i : (data[i] = find_root(data[i])); }
    int set_size(int i) { return - data[find_root(i)]; }
    int unite_sets(int i, int j) {
        i = find_root(i); j = find_root(j);
        if (i != j) {
            if (set_size(i) < set_size(j)) swap(i,j);
            data[i] += data[j];
            data[j] = i;
        }
        return i;
    }
    bool is_same(int i, int j) { return find_root(i) == find_root(j); }
};

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> x(n), y(n); repeat (i, n) scanf("%d%d", &x[i], &y[i]);
    // solve
    reversed_priority_queue<tuple<int, int, int> > que;
    auto add_edges_with = [&](function<int (int, int)> f) {
        vector<int> indices(n);
        iota(whole(indices), 0);
        sort(whole(indices), [&](int i, int j) { return f(x[i], y[i]) < f(x[j], y[j]); });
        repeat (k, n - 1) {
            int i = indices[k];
            int j = indices[k + 1];
            int dist = min(abs(x[i] - x[j]), abs(y[i] - y[j]));
            que.emplace(dist, i, j);
        }
    };
    add_edges_with([](int x, int y) { return x; });
    add_edges_with([](int x, int y) { return y; });
    ll result = 0;
    disjoint_sets ds(n);
    while (not que.empty()) {
        int dist, i, j; tie(dist, i, j) = que.top(); que.pop();
        if (not ds.is_same(i, j)) {
            result += dist;
            ds.unite_sets(i, j);
        }
    }
    // output
    printf("%lld\n", result);
    return 0;
}
```

<hr>

-   2018年  1月  3日 水曜日 11:11:48 JST
    -   距離の名前について勘違いしてたので修正
