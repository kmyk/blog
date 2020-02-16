---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-007-d/
  - /blog/2017/09/05/agc-007-d/
date: "2017-09-05T16:30:03+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc007/tasks/agc007_d" ]
---

# AtCoder Grand Contest 007: D - Shik and Game

自明DPの$O(N^2)$をsegment木とかで$O(N \log N)$で落とすやつでしょ知ってるけど$N \le 10^5$なので定数倍高速化で押し切るよ、って言いながらガチャガチャしてたらいつの間にか$O(N)$に落ちてしまっていた。レギュレーション違反。定数倍高速化でなんとかする方法は分からず。後$2$倍。本気でやればできるのかもだが、コンパイラに察してもらう範囲ではだめだった。

## solution

DP。$O(N)$。

まず同じ点を$3$回を越えて通る必要はないことを見る。図を書けばすぐ。これには$0 \le x\_i \le E$が成り立つことが効いている。

そこでDPをする。
$i$番目以降のみを考え$x\_i$に到着した直後から必要な最短時間を$\mathrm{dp}\_i$とする。
どこまでキャンディを配ってから$x\_i$に戻ってくるかを考えれば漸化式 $\mathrm{dp}\_l = \min \\{ \max \\{ T, 2(x\_{r-1} - r\_l) + (x\_r - x\_l) + \mathrm{dp}\_r \mid r \gt l \\}$。
そのままでは$O(N^2)$だが、内側の$\max$を消去し$\mathrm{dp}$は単調減少であることを使えば$O(N)$にできる。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

constexpr ll inf = ll(1e18)+9;
int main() {
    // input
    int n, e, t; scanf("%d%d%d", &n, &e, &t);
    vector<int> x(n); repeat (i, n) scanf("%d", &x[i]);
    // solve
    vector<ll> dp(n + 1, inf);
    dp[n] = e;
    int m = n;
    ll acc = inf;
    repeat_reverse (l, n) {
        for (; m - 1 >= l + 1 and t <= 2ll * (x[m - 1] - x[l]); -- m) {
            setmin(acc, 2ll * x[m - 1] + dp[m]);
        }
        dp[l] = min(acc - 2ll * x[l], t + dp[m]);
    }
    // output
    printf("%lld\n", dp[0]);
    return 0;
}
```

### 愚直 $O(N^2)$

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

constexpr ll inf = ll(1e18)+9;
int main() {
    // input
    int n, e, t; scanf("%d%d%d", &n, &e, &t);
    vector<int> x(n); repeat (i, n) scanf("%d", &x[i]);
    // solve
    x.push_back(e);
    vector<ll> dp(n + 1, inf);
    dp[n] = 0;
    repeat_reverse (l, n) {
        repeat_from (r, l + 1, n + 1) {
            setmin(dp[l], max<ll>(t, 2ll * (x[r - 1] - x[l])) + (x[r] - x[l]) + dp[r]);
        }
    }
    // output
    printf("%lld\n", x[0] + dp[0]);
    return 0;
}
```
