---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/437/
  - /blog/2016/10/29/yuki-437/
date: "2016-10-29T00:24:32+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp", "bit-dp" ]
"target_url": [ "http://yukicoder.me/problems/no/437" ]
---

# Yukicoder No.437 cwwゲーム

## solution

bit-DP。既に使ったindexの集合の上で素直にやればよい。$O(2^{\log\_{10} N}(\log\_{10} N)^3$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
int main() {
    vector<int> a; {
        string s; cin >> s;
        for (char c : s) a.push_back(c - '0');
    }
    vector<int> dp(1<<a.size());
    repeat (t, dp.size()) {
        repeat (k, a.size()) if (t&(1<<k)) {
            repeat (j, k) if (t&(1<<j) and a[j] == a[k]) {
                repeat (i, j) if (t&(1<<i) and a[i] != 0 and a[i] != a[j]) {
                    int u = t & (~(1<<i)) & (~(1<<j)) & (~(1<<k));
                    setmax(dp[t], dp[u] + a[i]*100 + a[j]*10 + a[k]);
                }
            }
        }
    }
    cout << *whole(max_element, dp) << endl;
    return 0;
}
```
