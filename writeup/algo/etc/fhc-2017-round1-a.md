---
layout: post
redirect_from:
  - /writeup/algo/etc/fhc-2017-round1-a/
  - /blog/2017/01/16/fhc-2017-round1-a/
date: "2017-01-16T03:04:29+09:00"
tags: [ "competitive", "writeup", "facebook-hacker-cup", "greedy", "dp" ]
"target_url": [ "https://www.facebook.com/hackercup/problem/1800890323482794/" ]
---

# Facebook Hacker Cup 2017 Round 1: Pie Progress

## solution

DP。$i$日目までで既に$j \ge i$個パイを買ってるときの費用の最小値を$f(i,j)$とする。パイは安い方から貪欲に買う。$O(N^2M)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int inf = 1e9+7;
int solve(int n, int m, vector<vector<int> > & c) {
    repeat (i,n) whole(sort, c[i]);
    vector<vector<int> > dp = vectors(n+1, n+1, inf);
    dp[0][0] = 0;
    repeat (i,n) {
        repeat_from (j,i,n+1) {
            int acc = 0;
            repeat (k,min(m+1,n-j+1)) {
                setmin(dp[i+1][j+k], dp[i][j] + acc + k*k);
                if (k < m) acc += c[i][k];
            }
        }
    }
    return dp[n][n];
}
int main() {
    int t; cin >> t;
    repeat (i,t) {
        int n, m; cin >> n >> m;
        vector<vector<int> > c = vectors(n, m, int());
        repeat (i,n) repeat (j,m) cin >> c[i][j];
        cout << "Case #" << i+1 << ": " << solve(n, m, c) << endl;
    }
    return 0;
}
```
