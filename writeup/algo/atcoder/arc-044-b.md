---
layout: post
redirect_from:
  - /blog/2015/09/29/arc-044-b/
date: 2015-09-29T23:40:33+09:00
tags: [ "atcoder", "competitive", "arc", "writeup" ]
---

# AtCoder Regular Contest 044 B - 最短路問題

時間がなかったが1日1問を絶やしたくなかったのでB問題。
これでARCのB問題が尽きてしまった。

<!-- more -->

## [B - 最短路問題](https://beta.atcoder.jp/contests/arc044/tasks/arc044_b) {#b}

overflowのバグが1つ生えた。すぐ気付けたが。やはり`#define int long long`すべきなのだろうか

### 問題

ある頂点と他の全ての頂点との距離が与えられる。そのような距離の条件を満たす単純グラフの数を求める。

### 解法

-   条件を満たせない場合について考える
    -   1番目の頂点と1番目の頂点の距離が0でない
    -   1番目の頂点と$n$番目($n \neq 1$)の頂点の距離が0
    -   1番目の頂点との距離が$a$である頂点がないが、1番目の頂点との距離が$b$ ($b > a$)である頂点がある
        -   結果的に、これは対処する必要はない
-   1番目以外であれば、何番目かの情報は不要
    -   1番目の頂点からある距離$d$である頂点がそれぞれいくつあるかだけを考えればよい
-   距離$d$の頂点は
    -   距離$d-1$の頂点と繋がってないといけない
    -   距離$e$ ($e \le d-2$)の頂点と繋がってないてはいけない
        -   逆向きに考えると、距離$e$ ($e \ge d+1$)の頂点と繋がってないてはいけない
-   つまり、距離$d$の頂点は
    -   1つ以上の距離$d-1$の頂点と繋がる
    -   0つ以上の距離$d$の頂点と繋がる
-   以上を実装する
    -   巾乗の計算だけで済む

### 解答

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
constexpr ll mod = 1000000007;
ll powi(ll a, ll b) {
    ll result = 1;
    ll e = a;
    for (int i = 0; (1ll << i) <= b; ++ i) {
        if ((1ll << i) & b) {
            result = result * e % mod;
        }
        e = e * e % mod;
    }
    return result;
}
using namespace std;
ll solve(int n, vector<int> const & a) {
    if (a[0] != 0) return 0;
    int l = *max_element(a.begin(), a.end());
    vector<ll> b(l+1);
    repeat (i,n) b[a[i]] += 1;
    if (b[0] >= 2) return 0;
    repeat (i,l+1) if (b[i] == 0) return 0;
    ll result = 1;
    repeat_from (i,1,l+1) {
        result = result * powi((powi(2, b[i-1]) - 1 + mod) % mod, b[i]) % mod;
        result = result * powi(2, b[i] * (b[i] - 1) / 2) % mod;
    }
    return result;
}
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    cout << solve(n, a) << endl;
    return 0;
}
```
