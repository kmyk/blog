---
layout: post
redirect_from:
  - /blog/2018/02/14/dwacon2018-final-c/
date: "2018-02-14T02:32:28+09:00"
tags: [ "competitive", "writeup", "atcoder", "dwacon", "dp", "sierpinski-gasket", "pascals-triangle", "optimization" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2018-final-open/tasks/dwacon2018_final_c" ]
---

# 第4回 ドワンゴからの挑戦状 本選: C - XOR ピラミッド

Sierpinskiのgasketのような図形が見えてすごく面白かった。
ただし解法が見えてからはつらかった。

## solution

Pascalの三角形の列上の区間和を$\bmod 2$で求める問題に帰着される。メモ化再帰で定数倍高速化して捩じ込む。計算量は分からず。たぶん非想定解。

最下段の各マス$i$から最上段のマスへの経路数$p\_i$をそれぞれ求めれば$\mathrm{ans} = \sum^{\text{xor}}\_i v\_i^{p\_i}$。
xorの性質から、それぞれの区間$[x, x + L\_i)$について区間中の$p\_i$の総和を$\bmod 2$で求める問題に帰着された。
つまりPascalの三角形の列の区間和。
Pascalの三角形は$\bmod 2$の場合Sierpinskiのgasketのような規則性を持つので、それに従って丁寧に計算。

単に丁寧に計算するだけだと$2$倍ほど間に合わないが、頑張ると通る:

-   末尾呼び出しを潰して最適化
-   区間の端点が$0$の並ぶ穴の中のとき、ずらす
-   `unordered_map<size_t, T>` に乗せる
-   `#pragma GCC optimize("O3")`

```
                               #
                              ###
                             #-#-#
                            ##-#-##
                           #---#---#
                          ###-###-###
                         #-#---#---#-#
                        ##-##-###-##-##
                       #-------#-------#
                      ###-----###-----###
                     #-#-#---#-#-#---#-#-#
                    ##-#-##-##-#-##-##-#-##
                   #---#-------#-------#---#
                  ###-###-----###-----###-###
                 #-#---#-#---#-#-#---#-#---#-#
                ##-##-##-##-##-#-##-##-##-##-##
               #---------------#---------------#
              ###-------------###-------------###
             #-#-#-----------#-#-#-----------#-#-#
            ##-#-##---------##-#-##---------##-#-##
           #---#---#-------#---#---#-------#---#---#
          ###-###-###-----###-###-###-----###-###-###
         #-#---#---#-#---#-#---#---#-#---#-#---#---#-#
        ##-##-###-##-##-##-##-###-##-##-##-##-###-##-##
       #-------#---------------#---------------#-------#
      ###-----###-------------###-------------###-----###
     #-#-#---#-#-#-----------#-#-#-----------#-#-#---#-#-#
    ##-#-##-##-#-##---------##-#-##---------##-#-##-##-#-##
   #---#-------#---#-------#---#---#-------#---#-------#---#
  ###-###-----###-###-----###-###-###-----###-###-----###-###
 #-#---#-#---#-#---#-#---#-#---#---#-#---#-#---#-#---#-#---#-#
##-##-##-##-##-##-##-##-##-##-###-##-##-##-##-##-##-##-##-##-##
```

## implementation

``` c++
#pragma GCC optimize("O3")
#pragma GCC target("avx")
#include <bitset>
#include <cassert>
#include <cstdio>
#include <numeric>
#include <unordered_map>
#include <vector>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

ll gasket(ll n, ll l, ll r) {
    assert (0 <= n);
    assert (0 <= l and l <= r and r <= 2 * n + 1);
    if (n <= 1) return r - l;
    if (r - l == 0) return 0;
    if (l != 0) return gasket(n, 0, r) - gasket(n, 0, l);
    assert (l == 0);
    if (n < r) return 2 * gasket(n, 0, n) + 1 - gasket(n, 0, 2 * n + 1 - r);
    assert (r <= n);
    ll  msb = 1ll << (63 - __builtin_clzll(n));
    ll hmsb = msb >> 1;
    ll k = n - msb;
    if (2 * k + 1 + (k < hmsb ? 0 : hmsb) <= r and r <= msb) r = 2 * k + 1;
    static unordered_map<size_t, ll> memo;
    auto key = hash<bitset<128> >{}((bitset<128>(n) << 64) | bitset<128>(r));
    if (memo.count(key)) return memo[key];
    ll acc = 0;
    if (hmsb <= k and k + 1 < r) {
        acc += gasket(k, k, k + hmsb);
        k -= hmsb;
        r -= hmsb;
    }
    acc += gasket(k, 0, min(2 * k + 1, r));
    if (msb <= r) acc += gasket(k, 0, r - msb);
    return memo[key] = acc;
}

int main() {
    // input
    int m; scanf("%d", &m);
    vector<int> v(m), l(m); REP (i, m) scanf("%d%d", &v[i], &l[i]);

    // solve
    ll n = (accumulate(ALL(l), 0ll) - 1) / 2;
    int result = 0;
    ll x = 0;
    REP (i, m) {
        if (gasket(n, x, x + l[i]) % 2 == 1) {
            result ^= v[i];
        }
        x += l[i];
    }

    // output
    printf("%d\n", result);
    return 0;
}
```
