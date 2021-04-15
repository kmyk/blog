---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/241/
  - /blog/2016/08/26/yuki-241/
date: "2016-08-26T01:16:42+09:00"
tags: [ "competitive", "writeup", "yukicoder", "random" ]
"target_url": [ "http://yukicoder.me/problems/no/241" ]
---

# Yukicoder No.241 出席番号(1)

乱択。
解となる列はおおよそ$(\frac{n-1}{n})^n \approx 0.36$ぐらいの確率で存在していると考えてよく、これは十分に高い。
不一致なものを適当にswapすることを繰り返すと、さらに効率がよい。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <set>
#include <random>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    if (whole(count, a, a[0]) == n and 0 <= a[0] and a[0] < n) {
        cout << -1 << endl; // all a_i is the same
    } else {
        vector<int> b(n); whole(iota, b, 0);
        set<int> c; repeat (i,n) if (a[i] == b[i]) c.insert(i);
        default_random_engine gen((random_device())());
        uniform_int_distribution<int> dist(0, n-1);
        while (not c.empty()) {
            int i = *c.begin();
            int j = i; while (j == i) j = dist(gen);
            swap(b[i], b[j]);
            c.erase(i);
            c.erase(j);
            if (a[i] == b[i]) c.insert(i);
            if (a[j] == b[j]) c.insert(j);
        }
        for (int it : b) cout << it << endl;
    }
    return 0;
}
```
