---
layout: post
alias: "/blog/2017/03/26/yahoo-procon-2017-final-c/"
date: "2017-03-26T11:26:39+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon", "simd", "optimization" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2017-final-open/tasks/yahoo_procon2017_final_c" ]
---

# 「みんなのプロコン」本選: C - 倍数クエリ

SIMDを意識しすぎてreadとcache missを増やしすぎてTLEし続けていた。精進が足りない。

## solution

愚直。$O(QN)$。

SIMDを意識しつつ適切に書けば通る。

## implementation

<https://beta.atcoder.jp/contests/yahoo-procon2017-final-open/submissions/1180256>

``` c++
#include <cstdio>
#include <cstdint>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
constexpr int max_n = 100000;
int32_t a[max_n];
int main() {
    int n, m, q; scanf("%d%d%d", &n, &m, &q);
    repeat (i,n) {
        scanf("%d", &a[i]);
        a[i] %= m;
    }
    while (q --) {
        int l, r, d; scanf("%d%d%d", &l, &r, &d); -- l; d %= m;
        int cnt = 0;
        for (int i = l; i < r; ++ i) {
            a[i] += d;
            if (a[i] >= m) a[i] -= m;
            cnt += not a[i];
        }
        printf("%d\n", cnt);
    }
    return 0;
}
```
