---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc-041-d/
  - /blog/2016/07/04/abc-041-d/
date: "2016-07-04T11:50:37+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc041/tasks/abc041_d" ]
---

# AtCoder Beginner Contest 041 D - 徒競走

解けず。解けないといけないやつだった。
丁寧に再帰して$O(N)$なのかな木にならないのがつらいなしかも$N \le 16$なんだよな、とか言ってたのすごくだめっぽい。

## solution

有向グラフのトポロジカルソートの数。bit-DPする。$O(N2^N)$。

$\mathrm{dp} : \mathcal{P}(N) \to \mathbb{N}$を、$\mathrm{dp}(X)$は頂点を$X$に制限したときのトポロジカルソートの数として更新する。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
template <typename T, typename X> auto vectors(T a, X x) { return vector<T>(x, a); }
template <typename T, typename X, typename Y, typename... Zs> auto vectors(T a, X x, Y y, Zs... zs) { auto cont = vectors(a, y, zs...); return vector<decltype(cont)>(x, cont); }
int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<vector<bool> > g = vectors(false, n, n);
    repeat (i,m) {
        int x, y; scanf("%d%d", &x, &y); -- x; -- y;
        g[x][y] = true;
    }
    // compute
    repeat (k,n) repeat (i,n) repeat (j,n) if (g[i][k] and g[k][j]) g[i][j] = true; // warshall-floyd
    vector<int> u(n);
    repeat (i,n) repeat (j,n) if (g[i][j]) u[i] |= 1<<j;
    vector<ll> dp(1<<n);
    dp[0] = 1;
    repeat (s,1<<n) {
        repeat (j,n) if (s & (1<<j)) {
            int t = s & ~ (1<<j);
            if ((u[j] & t) == 0) {
                dp[s] += dp[t];
            }
        }
    }
    // output
    printf("%lld\n", dp[(1<<n)-1]);
    return 0;
}
```
