---
layout: post
alias: "/blog/2016/06/10/tdpc-i/"
title: "Typical DP Contest I - イウィ"
date: 2016-06-10T20:25:42+09:00
tags: [ "competitive", "writeup", "atcoder", "typical-dp-contest", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/tdpc/tasks/tdpc_iwi" ]
---

kmjpさんの[解説](http://kmjp.hatenablog.jp/entry/2013/09/06/0930)を見ました。

## solution

区間$[l,r)$が取り除けるかそれぞれ調べ、これを元に区間$[l,n)$で取り除ける数を数える。$O(N^3)$。

区間$[l,r)$が取り除けるのは、

-   $l = r$のとき
-   ある$m \in [l,r)$があって、
    -   $s_l = \operatorname{i}, s_m = \operatorname{w}, s\_{r-1} = \operatorname{i}$であり、区間$[l+1,m-1]$と区間$[m+1,r-1]$が取り除けるとき
    -   区間$[l,m)$と区間$[m,r)$が取り除けるとき

これを、区間の長さ$r-l$の小さい順に更新していけばよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
template <typename T, typename X> auto vectors(T a, X x) { return vector<T>(x, a); }
template <typename T, typename X, typename Y, typename... Zs> auto vectors(T a, X x, Y y, Zs... zs) { auto cont = vectors(a, y, zs...); return vector<decltype(cont)>(x, cont); }
int main() {
    string s; cin >> s;
    int n = s.length();
    vector<vector<bool> > removable = vectors(false, n+1, n+1); // [l, r)
    repeat (l,n) removable[l][l] = true;
    repeat_from (len,3,n+1) {
        repeat (l,n) {
            int r = l+len;
            if (n < r) break;
            repeat_from (m,l,r+1) {
                if (s[l] == 'i' and s[m] == 'w' and s[r-1] == 'i'
                        and removable[l+1][m]
                        and removable[m+1][r-1]) {
                    removable[l][r] = true; // remove a new iwi
                    break;
                }
                if (removable[l][m] and removable[m][r]) {
                    removable[l][r] = true; // merge two removables
                    break;
                }
            }
        }
    }
    vector<int> dp(n+1); // [l, n)
    repeat_reverse (l,n) {
        dp[l] = dp[l+1];
        repeat_from (r,l,n+1) if (removable[l][r]) {
            setmax(dp[l], r-l + dp[r]);
        }
    }
    cout << dp[0] / 3 << endl;
    return 0;
}
```
