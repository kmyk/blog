---
layout: post
redirect_from:
  - /writeup/algo/codeforces/358-d/
  - /blog/2016/03/24/cf-358-d/
date: 2016-03-24T23:33:17+09:00
tags: [ "competitive", "writeup", "codeforces" ]
---

# Codeforces Round #208 (Div. 2) D. Dima and Hares

この回のA,B,Cは嫌いだが、この問題はそうでもなかった。

## [D. Dima and Hares](http://codeforces.com/contest/358/problem/D)

### 問題

うさぎが$N$匹、一列に並んでいる。
適当な順番で餌をやる。
うさぎ$i$に餌をやったとき、その隣接するうさぎで既に餌を貰ったものが何匹($0, 1 or 2$)あるかによって、そのうさぎの得られる満足度は異なる($a_i, b_i, c_i$)。
満足度の総和を最大化し、その値を答えよ。

### 解法

DP。$i$番目未満のうさぎの得る満足度を全て確定させ、$i$番目のうさぎに餌をやるとき$i-1$番目のうさぎは餌を既に貰っているかいないかを$j$とし、$dp\_{i,j}$を更新する。$O(N)$。

両端の処理を忘れずに。

### 実装

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
using namespace std;
const int inf = 1e9;
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    vector<int> b(n); repeat (i,n) cin >> b[i];
    vector<int> c(n); repeat (i,n) cin >> c[i];
    vector<vector<int> > dp(n+1, vector<int>(2));
    dp[0][0] = - inf;
    repeat (i,n) {
        setmax(dp[i+1][0], dp[i][0] + b[i]);
        setmax(dp[i+1][0], dp[i][1] + a[i]);
        setmax(dp[i+1][1], dp[i][0] + c[i]);
        setmax(dp[i+1][1], dp[i][1] + b[i]);
    }
    cout << dp[n][0] << endl;
    return 0;
}
```
