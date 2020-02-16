---
layout: post
redirect_from:
  - /blog/2016/07/30/tenka1-2016-quala-b/
date: "2016-07-30T23:24:29+09:00"
tags: [ "competitive", "wirteup", "atcoder", "tenka1-programmer-contest", "tree", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/tenka1-2016-quala/tasks/tenka1_2016_qualA_b" ]
---

# 天下一プログラマーコンテスト2016予選A: PackDrop

## solution

辺に整数重みを適当に載せて、根から各葉への距離を指定された値にする問題。
葉から根に向かって、貪欲にまとめ上げていけばよい。$O(N)$。

とりあえずPackDropは全て葉の直前の辺に載せるとする。
ある(根でない)頂点から見て、その子への辺の全てに$1$つ以上のPackDropが存在すれば、それらを$1$つずつ取り除いて自分の親への辺に載せかえることができる。これを可能な限り繰り返せば最適な状態で止まる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <numeric>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const ll inf = ll(1e18)+9;
int main() {
    // input
    int n, m; cin >> n >> m;
    vector<int> parent(n);
    vector<vector<int> > children(n);
    parent[0] = -1;
    repeat_from (i,1,n) {
        cin >> parent[i];
        children[parent[i]].push_back(i);
    }
    vector<int> b(m);
    vector<ll> c(n);
    repeat (i,m) {
        cin >> b[i];
        cin >> c[b[i]];
    }
    // coalesce greedily
    function<void (int)> dfs = [&](int i) {
        if (children[i].empty()) return;
        ll acc = inf;
        for (int j : children[i]) {
            dfs(j);
            setmin(acc, c[j]);
        }
        for (int j : children[i]) {
            c[j] -= acc;
        }
        c[i] += acc;
    };
    for (int j : children[0]) {
        dfs(j);
    }
    // output
    ll ans = whole(accumulate, c, 0ll);
    cout << ans << endl;
    return 0;
}
```
