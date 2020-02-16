---
layout: post
redirect_from:
  - /blog/2017/03/12/agc-011-a/
date: "2017-03-12T22:48:16+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc011/tasks/agc011_a" ]
---

# AtCoder Grand Contest 011: A - Airport Bus

## solution

sortして貪欲。$O(N)$。

まだ乗るバスが決まってない人の中で到着時刻が最小の人を人$l$とする。
この人の乗れるバスがあるなら乗り、そうでないなら時刻$T_i + K$に出発するバスを作るのが妥当である。
$T$をsortしておけば、これは配列を一度なめるだけで実行できる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    int n, c, k; cin >> n >> c >> k;
    vector<int> t(n); repeat (i,n) cin >> t[i];
    whole(sort, t);
    int cnt = 0;
    int l = 0;
    while (l < n) {
        int r = l;
        while (r < n and r - l < c and t[r] <= t[l] + k) ++ r;
        ++ cnt;
        l = r;
    }
    cout << cnt << endl;
    return 0;
}
```
