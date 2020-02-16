---
layout: post
redirect_from:
  - /blog/2016/06/27/icpc-2016-domestic-d/
date: 2016-06-27T13:01:55+09:00
tags: [ "competitive", "writeup", "icpc", "dp", "dp-on-intervals" ]
---

# ACM-ICPC 2016 国内予選 D: ダルマ落とし

-   <http://icpcsec.storage.googleapis.com/icpc2016-domestic/problems/all_ja.html#section_D>
-   <http://icpc.iisf.or.jp/past-icpc/domestic2016/judgedata/D/>

類問: [Typical DP Contest I - イウィ](https://beta.atcoder.jp/contests/tdpc/tasks/tdpc_iwi)

## solution

区間DP。$O(N^3)$。

以下のふたつがある。

1.  ある区間の全てが叩き出せるかをDPで求めて、全体で叩き出せる数を再度DPで求める。
2.  ある区間の中で叩き出せる要素の数をDPで求める。

ある区間$[l,r)$が叩き出せるとは、

-   区間$[l+1,r-1)$が叩き出せかつ$\|w\_{r-1} - w_l\| \le 1$を満たす。
-   ある$m \in [l,r)$があって、区間$[l,m)$と区間$[m,r)$が共に叩き出せる。

なので、これをやる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
template <typename T, typename X> auto vectors(T a, X x) { return vector<T>(x, a); }
template <typename T, typename X, typename Y, typename... Zs> auto vectors(T a, X x, Y y, Zs... zs) { auto cont = vectors(a, y, zs...); return vector<decltype(cont)>(x, cont); }
int main() {
    while (true) {
        int n; cin >> n;
        if (n == 0) break;
        vector<int> w(n); repeat (i,n) cin >> w[i];
        vector<vector<int> > dp = vectors(0, n+1, n+1); // [l, r)
        repeat (len,n+1) {
            repeat (l,n) {
                int r = l + len;
                if (n < r) break;
                if (0 <= l+1 and l+1 <= r-1 and r-1 <= n) {
                    if (dp[l+1][r-1] == (r-1) - (l+1) and abs(w[r-1] - w[l]) <= 1) setmax(dp[l][r], dp[l+1][r-1] + 2);
                }
                repeat_from (m,l,r+1) {
                    setmax(dp[l][r], dp[l][m] + dp[m][r]);
                }
            }
        }
        cout << dp[0][n] << endl;
    }
    return 0;
}
```
