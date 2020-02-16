---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-028-d/
  - /blog/2017/02/23/arc-028-d/
date: "2017-02-23T23:52:33+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "loop-unrolling", "cache", "factoring-out", "lie" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc028/tasks/arc028_4" ]
---

# AtCoder Regular Contest 028: D - 注文の多い高橋商店

$10^9$はloopの中身が十分軽くないと厳しいと認識してたが、やればACに持っていける量という認識に改めるべきかも。

## solution

簡単に前処理 + 定数倍を頑張る。$O(M(N + Q))$。

区間$[0,k)$で$l$個使う方法の数$\mathrm{dp}\_L(k,l)$と区間$(k,N)$で$r$個使う方法の数$\mathrm{dp}\_R(k,r)$をそれぞれ$O(NM)$で前もって求めておく。
するとクエリ$(k,x)$について答え$\mathrm{ans} = \sum_l \mathrm{dp}\_L(k,l) \cdot \mathrm{dp}\_R(k,M-l-x)$であり、クエリあたり$O(M)$となる。

定数倍最適化に関して、以下をすれば通った。

-   loop unrolling
-   prefetchが効くようreverse
-   (コンパイラがやってくれてなかったので) 一時変数へのくくり出し

## implementation

<https://beta.atcoder.jp/contests/arc028/submissions/1128915>

``` c++
#include <cstdio>
#include <algorithm>
#define repeat(i,n) for (int i = 0; i < (n); ++i)
#define repeat_from(i,m,n) for (int i = (m); i < (n); ++i)
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
typedef long long ll;
using namespace std;
#define MAX_N 2000
#define MAX_M 2000
const int mod = 1000000007;
int a[MAX_N];
int dpl[MAX_N+1][MAX_M+1];
int dpr[MAX_N+1][MAX_M+1];
ll dpacc[MAX_M+2];
int main() {
    // input
    int n, m, q; scanf("%d%d%d", &n, &m, &q);
    repeat (i,n) scanf("%d", &a[i]);
    // prepare
    //     left
    dpl[0][0] = 1;
    repeat_from (i,1,n+1) {
        dpacc[0] = 0;
        repeat (j,m+1) dpacc[j+1] = dpacc[j] + dpl[i-1][j];
        repeat (j,m+1) dpl[i][j] = (dpacc[j+1] - dpacc[max(0, j-a[i-1])]) % mod;
    }
    //     right
    dpr[n][0] = 1;
    repeat_reverse (i,n) {
        dpacc[0] = 0;
        repeat (j,m+1) dpacc[j+1] = dpacc[j] + dpr[i+1][j];
        repeat (j,m+1) dpr[i][j] = (dpacc[j+1] - dpacc[max(0, j-a[i])]) % mod;
    }
    repeat (i,n+1) {
        reverse(dpr[i], dpr[i]+MAX_M+1);
    }
    // query
    repeat (query,q) {
        int k, x; scanf("%d%d", &k, &x); -- k;
        ll acc = 0;
        int *l = dpl[k];
        int *r = dpr[k+1] + MAX_M-m+x; // binding is required for optimization
        int j = 0;
        for (; j < m+1-x - 16; j += 16) {
            acc += l[j+ 0] *(ll) r[j+ 0] % mod;
            acc += l[j+ 1] *(ll) r[j+ 1] % mod;
            acc += l[j+ 2] *(ll) r[j+ 2] % mod;
            acc += l[j+ 3] *(ll) r[j+ 3] % mod;
            acc += l[j+ 4] *(ll) r[j+ 4] % mod;
            acc += l[j+ 5] *(ll) r[j+ 5] % mod;
            acc += l[j+ 6] *(ll) r[j+ 6] % mod;
            acc += l[j+ 7] *(ll) r[j+ 7] % mod;
            acc += l[j+ 8] *(ll) r[j+ 8] % mod;
            acc += l[j+ 9] *(ll) r[j+ 9] % mod;
            acc += l[j+10] *(ll) r[j+10] % mod;
            acc += l[j+11] *(ll) r[j+11] % mod;
            acc += l[j+12] *(ll) r[j+12] % mod;
            acc += l[j+13] *(ll) r[j+13] % mod;
            acc += l[j+14] *(ll) r[j+14] % mod;
            acc += l[j+15] *(ll) r[j+15] % mod;
        }
        for (; j < m+1-x; ++ j) {
            acc += l[j] *(ll) r[j] % mod;
        }
        printf("%lld\n", acc % mod);
    }
    return 0;
}
```
