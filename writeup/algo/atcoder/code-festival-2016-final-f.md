---
layout: post
redirect_from:
  - /blog/2016/12/24/code-festival-2016-final-f/
date: "2016-12-24T21:02:34+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "dp", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-final-open/tasks/codefestival_2016_final_f" ]
---

# CODE FESTIVAL 2016 Final: F - Road of the King

$1000$点のわりに苦労なく解けた。
本番で触らなかったのが悔やまれる。

## solution

DP。$O(N^2M)$。

単純に考えると、各頂点を始めて訪れる時刻に注目したい。
$1$は最後に訪れなければならないとして、その他の頂点をいくつ訪れたかでDP (時刻と訪問数から数、$\mathrm{dp}: (M+1) \times (N+1) \to \mathbb{N}$)にする、というのが思い浮かぶかもしれない。
しかし$1$を最後に訪れるというのには嘘で、$N = 5$のとき$1 \to 2 \to 3 \to 1 \to 2 \to 4 \to 5 \to 2$のような遷移が反例。

このような反例は$1$を含む強連結成分によるもの。
そこで$1$を含む強連結成分の大きさを状態に加えて、$\mathrm{dp}: (M+1) \times (N+1) \times (N+1) \to \mathbb{N}$という関数にすれば答えがでる。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
typedef long long ll;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int mod = 1e9+7;
int main() {
    int n, m; cin >> n >> m;
    auto dp = vectors(m+1, n+1, n+1, ll());
    dp[0][1][0] = 1;
    repeat (i,m) {
        repeat (j,n+1) {
            repeat (k,n+1) if (j+k <= n) {
                dp[i][j][k] %= mod;
                dp[i+1][j+k][0] += dp[i][j][k] * j % mod;
                dp[i+1][j][k]   += dp[i][j][k] * k % mod;
  if (k+1 <= n) dp[i+1][j][k+1] += dp[i][j][k] * (n-j-k) % mod;
            }
        }
    }
    cout << dp[m][n][0] % mod << endl;
    return 0;
}
```
