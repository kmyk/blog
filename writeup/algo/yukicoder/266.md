---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/266/
  - /blog/2016/12/13/yuki-266/
date: "2016-12-13T18:26:32+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp" ]
"target_url": [ "http://yukicoder.me/problems/no/266" ]
---

# Yukicoder No.266 最終進化を目指せ

## solution

素直なDPでよい。$O(\sum\_{0 \le i \le N} s_i)$。

$i$番目の進化で$j$個覚醒したカードを作るのに何枚の未進化のカードが必要かを$\mathrm{dp}(i,j)$とすればよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int inf = 1e9+7;
int main() {
    int n; cin >> n;
    vector<int> s(n+1); repeat (i,n+1) cin >> s[i];
    vector<vector<int> > dp = vectors(n+1, s[n]+1, inf);
    dp[0][0] = 1;
    repeat (i,n+1) {
        repeat (j,s[i]+1) {
            if (i >= 1) {
                setmin(dp[i][j], dp[i-1][j] + 1);
            }
            if (j >= 1) {
                repeat (a,j) {
                    int b = j-a-1;
                    setmin(dp[i][j], dp[i][a] + dp[i][b]);
                }
            }
        }
    }
    repeat (j,s[n]+1) {
        if (j) cout << ' ';
        cout << dp[n][j];
    }
    cout << endl;
    return 0;
}
```
