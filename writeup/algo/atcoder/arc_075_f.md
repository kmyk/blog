---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_075_f/
  - /writeup/algo/atcoder/arc-075-f/
  - /blog/2017/06/03/arc-075-f/
date: "2017-06-03T22:58:03+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc075/tasks/arc075_d" ]
---

# AtCoder Regular Contest 075: F - Mirrored

雑に取った探索範囲の上界が少し小さかったのでちょうど$1$WAしたまま取れず。
レート$-15$した。

## solution

上手く式変形すれば上からDPのように決めていける。
計算量はよく分からないけど$O(2^{\log\_{10}{\frac{d}{9}} / 2})$とかで抑えられそう。

例えば$N$が$5$桁だとすると$N = 10000a + 1000b + 100c + 10d + e$で$a \ne 0$。
$\mathrm{rev}(N) - N = (10000e + 1000d + 100c + 10b + a) - (10000a + 1000b + 100c + 10d + e) = 9999(e - a) + 990(d - b) + 0c$。
このように常に$9 \mid \mathrm{rev}(N) - N$なので$9 \nmid D$なら答えは$0$。

例えば$\frac{\mathrm{rev}(N) - N}{9} = 1111(e - a) + 110(d - b) + 0c$を上手く決めて$\frac{D}{9}$に一致させたい。
係数が大きい側から順に決めていくと、$i$番目のものでどれを使うべきかは$10^i$の桁を見れば定まる。
$0 \le a, b \le 9$のとき$-9 \le a - b 9$なので一意ではないにせよ探索範囲は十分小さくなるので、これを桁数$k$ごとに再帰的にやれば終わり。

ただし桁数$k$は$D$の桁数の$2$倍ぐらいまで必要なようなので注意すること。

## implementation

``` c++
#include <cstdio>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;

array<ll, 19> repunit;
array<ll, 19> ten;
ll go(ll d, int log_n, int i) {
    ll e = repunit[log_n+1-i] - repunit[i];
    if (e == 0) {
        return 10 * int(d == 0);
    } else if (e < 0) {
        return int(d == 0);
    } else {
        auto digits = [&](int k) {
            int cnt = 0;
            repeat (a, 10) repeat (b, 10) {
                if (i == 0 and b == 0) continue;
                if (a - b == k) cnt += 1;
            }
            return cnt;
        };
        ll acc = 0;
        repeat_from (k, -9, 9+1) {
            if ((d - k * e) % ten[i+1] == 0) {
                acc += go(d - k * e, log_n, i + 1) * digits(k);
            }
        }
        return acc;
    }
}
ll solve(ll d) {
    repunit[0] = 0; repeat (i, repunit.size()-1) repunit[i+1] = repunit[i] * 10 + 1;
    ten[0] = 1; repeat (i, ten.size()-1) ten[i+1] = ten[i] * 10;
    if (d % 9 != 0) return 0;
    d /= 9;
    ll result = 0;
    repeat (n, 18) {
        result += go(d, n, 0);
    }
    return result;
}

int main() {
    int d; scanf("%d", &d);
    printf("%lld\n", solve(d));
    return 0;
}
```
