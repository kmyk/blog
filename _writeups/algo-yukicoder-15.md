---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/15/
  - /blog/2017/01/08/yuki-15/
date: "2017-01-08T14:44:57+09:00"
tags: [ "competitive", "writeup", "yukicoder", "branch-and-bound", "lie" ]
"target_url": [ "http://yukicoder.me/problems/no/15" ]
---

# Yukicoder No.15 カタログショッピング

## solution

分枝限定法。計算量は分からず。

加速として、事前に$P$を降順に並べておく、累積和を取って上限を$O(1)$で出す、をしておく。
出力は$50$行以下の保証があるので適当に貯めて最後にsortすればよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
int main() {
    int n; ll s; cin >> n >> s;
    vector<ll> p(n); repeat (i,n) cin >> p[i];
    vector<int> tr(n); whole(iota, tr, 0);
    whole(sort, tr, [&](int i, int j) { return p[i] > p[j]; });
    vector<ll> acc(n+1); repeat (i,n) acc[i+1] = acc[i] + p[tr[i]];
    vector<vector<int> > result;
    vector<int> path;
    function<void (int, ll)> go = [&](int i, ll q) {
        if (q == s) result.push_back(path);
        if (q >= s) return;
        if (q + acc[n] - acc[i] < s) return;
        if (i == n) return;
        go(i+1, q);
        path.push_back(tr[i]);
        go(i+1, q + p[tr[i]]);
        path.pop_back();
    };
    go(0, 0);
    for (auto & path : result) whole(sort, path);
    whole(sort, result);
    for (auto & path : result) {
        repeat (i,path.size()) cout << (i ? " " : "") << path[i]+1;
        cout << endl;
    }
    return 0;
}
```
