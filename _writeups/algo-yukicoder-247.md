---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/247/
  - /blog/2016/04/19/yuki-247/
date: 2016-04-19T21:15:33+09:00
tags: [ "competitive", "writeup", "yukicoder", "dp" ]
"target_url": [ "http://yukicoder.me/problems/678" ]
---

# Yukicoder No.247 線形計画問題もどき

## problem

-   min: $\Sigma\_{i=1}^{N} x_i$
-   sub to: $\Sigma\_{i=1}^{N} a_ix_i = C$
-   sub to: $x_1, x_2, \dots, x_N \in \mathbb{N}$

## solution

DP. $O(NC)$.

DPをする。
$a$との内積が$c$になるような$x$の総和の最小値$dp_c$を$O(N)$で$C$回更新する。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
template <class T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }
using namespace std;
const int inf = 1e9+7;
int main() {
    int c, n; cin >> c >> n;
    vector<int> as(n); repeat (i,n) cin >> as[i];
    vector<int> dp(c+1, inf);
    dp[0] = 0;
    repeat_from (i,1,c+1) {
        for (int a : as) {
            if (0 <= i-a) {
                setmin(dp[i], dp[i-a] + 1);
            }
        }
    }
    cout << (dp[c] == inf ? -1 : dp[c]) << endl;
    return 0;
}
```
