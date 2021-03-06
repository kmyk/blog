---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/14/
  - /blog/2017/01/04/yuki-14/
date: "2017-01-04T18:21:35+09:00"
tags: [ "competitive", "writeup", "yukicoder", "lcm" ]
"target_url": [ "http://yukicoder.me/problems/no/14" ]
---

# Yukicoder No.14 最小公倍数ソート

問題文に愚直で通ると書いてあったので愚直で通してしまった。
$A_i$が小さいことを利用して約数ごとに適当にやればできそう、というところまで考えたので許して。

## solution

毎回最小値を求めてswap。互除法の分と併せて$O(N^2 \log A_i)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <typename T> T gcd(T a, T b) { while (a) { b %= a; swap(a, b); } return b; }
template <typename T> T lcm(T a, T b) { return (a * b) / gcd(a,b); }
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    repeat (i,n-1) {
        auto it = min_element(a.begin() + i+1, a.end(), [&](int b, int c) {
            return make_pair(lcm(a[i], b), b) < make_pair(lcm(a[i], c), c);
        });
        swap(a[i+1], *it);
    }
    repeat (i,n) cout << (i ? " " : "") << a[i]; cout << endl;
    return 0;
}
```
