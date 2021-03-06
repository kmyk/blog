---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/168/
  - /blog/2016/08/31/yuki-168/
date: "2016-08-31T03:31:50+09:00"
tags: [ "competitive", "writeup", "yukicoder", "union-find-tree", "graph" ]
"target_url": [ "http://yukicoder.me/problems/no/168" ]
---

# Yukicoder No.168 ものさし

考えられる全ての辺を短い順に追加していって、$P_1$と$P_N$が連結になった時に追加した辺の長さが答え。
連結性はunion-find木で判定してやれば、$O(N^2\alpha(N))$。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
struct disjoint_sets {
    vector<int> xs;
    explicit disjoint_sets(size_t n) : xs(n, -1) {}
    bool is_root(int i) { return xs[i] < 0; }
    int find_root(int i) { return is_root(i) ? i : (xs[i] = find_root(xs[i])); }
    int set_size(int i) { return - xs[find_root(i)]; }
    int union_sets(int i, int j) {
        i = find_root(i); j = find_root(j);
        if (i != j) {
            if (set_size(i) < set_size(j)) swap(i,j);
            xs[i] += xs[j];
            xs[j] = i;
        }
        return i;
    }
    bool is_same(int i, int j) { return find_root(i) == find_root(j); }
};
struct edge_t { int i, j; ll dist; };
bool operator < (edge_t const & a, edge_t const & b) { return a.dist < b.dist; } // weak ordering
int main() {
    // input
    int n; cin >> n;
    vector<ll> x(n), y(n); repeat (i,n) cin >> x[i] >> y[i];
    // compute
    vector<edge_t> que;
    repeat (j,n) {
        repeat (i,j) {
            ll dist = ceill(hypotl(x[j] - x[i], y[j] - y[i]));
            que.push_back((edge_t) { i, j, dist });
        }
    }
    whole(sort, que);
    disjoint_sets t(n);
    ll ans = 0;
    for (edge_t e : que) {
        ans = e.dist;
        t.union_sets(e.i, e.j);
        if (t.is_same(0, n-1)) break;
    }
    assert (t.is_same(0, n-1));
    // output
    if (ans % 10 != 0) ans += 10 - ans % 10;
    cout << ans << endl;
    return 0;
}
```
