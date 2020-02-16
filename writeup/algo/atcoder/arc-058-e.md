---
layout: post
redirect_from:
  - /blog/2016/07/23/arc-058-e/
date: "2016-07-23T23:10:45+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "bit-dp" ]
---

# AtCoder Regular Contest 058 E - 和風いろはちゃん / Iroha and Haiku

-   <https://beta.atcoder.jp/contests/arc058/tasks/arc058_c>
-   editorial: <https://beta.atcoder.jp/contests/arc058/data/arc/058/editorial.pdf>

解けず。

## solution

XYZを含まないものを数える。
合計が$x+y+z$未満の列のみ覚えておけばよく、これは$x+y+z-1$bitの$2$進数にencodeできる。
$O(N2^{x+y+z-1})$。

XYZを含まないものを数え、$10^N$から引けばよい。
左から順に見ていくことを考える。
単純に貪欲に数えることはできないので、過去に見た値を何らかの形で持たなければならない。
覚えておくべき値は、合計が$X+Y+Z-1 \le 16$の範囲だけでよい。
例えば$(1,2,1,4,2)$の様な列であるが、これを`1101100010`のように、$1$進数表記のようにして連結したものとして持てば、これは長さが高々$16$となり持てる。
bit DPををして、$2^{X+Y+Z-1} + 2^{Y+Z-1} + 2^{Z-1}$に対応する文字列(たとえば$(X,Y,Z) = (5,7,5)$なら`1000100000010000`)を特定の形で含まないような列を数え上げればよい。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
template <typename T, typename X> auto vectors(T a, X x) { return vector<T>(x, a); }
template <typename T, typename X, typename Y, typename... Zs> auto vectors(T a, X x, Y y, Zs... zs) { auto cont = vectors(a, y, zs...); return vector<decltype(cont)>(x, cont); }
bool subset(int s, int t) { return (s & t) == s; }
const int mod = 1e9+7;
int main() {
    int n, x, y, z; scanf("%d%d%d%d", &n, &x, &y, &z);
    int l = x+y+z-1;
    int mask = (1<<l)-1;
    int forbidden = (1 << (x+y+z-1)) | (1 << (y+z-1)) | (1 << (z-1));
    vector<vector<ll> > dp = vectors(0ll, n+1, 1<<l);
    dp[0][0] = 1;
    repeat (i,n) {
        repeat_from (a,1,10+1) {
            repeat (s,1<<l) {
                int t = (s << a) | (1 << (a-1));
                if (subset(forbidden, t)) continue;
                dp[i+1][t & mask] += dp[i][s];
            }
        }
        repeat (s,1<<l) dp[i+1][s] %= mod;
    }
    ll ans = 1; repeat (i,n) ans = ans * 10 % mod;
    repeat (s,1<<l) ans -= dp[n][s];
    ans = (ans % mod + mod) % mod;
    printf("%lld\n", ans);
    return 0;
}
```
