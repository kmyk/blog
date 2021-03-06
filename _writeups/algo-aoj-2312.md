---
layout: post
redirect_from:
  - /writeup/algo/aoj/2312/
  - /blog/2017/12/08/aoj-2312/
date: "2017-12-08T06:03:45+09:00"
tags: [ "competitive", "writeup", "aoj", "dp" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2312" ]
---

# AOJ 2312. Magical Girl Sayaka-chan

ちょっと苦戦した。`partial_sum`でoverflowするやつもした。

## solution

DP。$O(N^2)$。

もし直線状に並べるのであれば単にsortするのが最適。
環状であるのでそうはいかないが、最適なら広義単調増加な部分と広義単調減少な部分のふたつからなることが言える。
つまり音符を$A, B$に分け$\mathrm{sort}(A) \oplus \mathrm{rev}(\mathrm{sort}(B))$のような形のものが最適。
これを両端から構成していくことを考えよう。
$A, B$のどちらに入れるかを$a$個目の音符まで決めて、最後に$B$側に入った音符が$b$であるとき、それまでの部分のペナルティの総和を$\mathrm{dp}(a, b)$とする。
そして最後に貼り合せる点でのペナルティも考慮して$\mathrm{ans} = \min\_{b \le N-2} \mathrm{dp}(N-1, b)$が答え。


## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

constexpr ll inf = ll(1e18)+9;
int main() {
    // input
    int n, m, l; scanf("%d%d%d", &n, &m, &l);
    vector<int> k(n); repeat (i, n) { scanf("%d", &k[i]); -- k[i]; }
    vector<int> s(m); repeat (i, m) scanf("%d", &s[i]);
    // solve
    sort(whole(k));
    vector<ll> s_acc(m + 1);
    repeat (i, m) s_acc[i + 1] = s_acc[i] + s[i];
    auto penalty = [&](int a, int b) { if (a > b) swap(a, b); return (s_acc[k[b] + 1] - s_acc[k[a]]) / l; };
    auto dp = vectors(n, n, inf);
    dp[1][0] = penalty(0, 1);
    repeat (a, n - 1) {
        repeat (b, a) {
            setmin(dp[a + 1][a], dp[a][b] + penalty(b, a + 1));
            setmin(dp[a + 1][b], dp[a][b] + penalty(a, a + 1));
        }
    }
    ll result = inf;
    repeat (c, n - 1) {
        setmin(result, dp[n - 1][c] + penalty(n - 1, c));
    }
    // output
    printf("%lld\n", result);
    return 0;
}
```
