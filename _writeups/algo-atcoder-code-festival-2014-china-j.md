---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2014-china-j/
  - /blog/2017/02/22/code-festival-2014-china-j/
date: "2017-02-22T23:44:51+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2014-china/tasks/code_festival_china_j" ]
---

# code festival 2014 上海: J - XORAND

SIMDの練習問題にと思ったのに、SIMDを書き始める前に通ってしまった。
clangさんは賢すぎるので何も言わずともvector化されてしまってるようだ。
2014年の問題なので当時は違ったのだろう。

## problem

最初に列$A$が与えられる。クエリ$[l-1,r)$が与えられるのでそれぞれについて、$m = \max \\{ {\bigwedge\mkern-15mu\bigwedge}\_{l-1 \le i \lt m} A_i - \bigoplus\_{m \le i \lt r} A_i \mid l-1 \lt m \lt r-1 \\}$を答えよ。
ただしクエリの先読みはできないものとする。

## solution

愚直っぽくやる。$O(NQ)$。

xorについては累積和を取っておいて適当に。
andについては高々$31$回しか変化しないので、bitごとに次の変化する位置のtableを持っておいて飛ぶようにする。

## implementation

``` c++
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
typedef long long ll;
using namespace std;
const ll inf = ll(1e18)+9;
#define N_MAX 100000
int32_t a[N_MAX];
int32_t xor_acc[N_MAX+1];
int and_skip[N_MAX][31];
int main() {
    // input
    int n, q; scanf("%d%d", &n, &q);
    repeat (i,n) scanf("%u", &a[i]);
    // prepare
    xor_acc[0] = 0;
    repeat (i,n) xor_acc[i+1] = xor_acc[i] ^ a[i];
    repeat (k,31) and_skip[n-1][k] = n;
    repeat_reverse (i,n-1) {
        repeat (k,31) {
            and_skip[i][k] = and_skip[i+1][k];
            if (not (a[i+1] & (1<<k))) and_skip[i][k] = i+1;
        }
    }
    // query
    ll m = - inf;
    while (q --) {
        // input
        int l, r; scanf("%d%d", &l, &r);
        if (m == - inf) {
            -- l;
        } else {
            l = (l + abs(m)) % n;
            r = (r + abs(m)) % n + 1;
        }
        // solve
        m = - inf;
        int32_t d = a[l];
        for (int i = l; i < r-1; ) {
            int ni = r-1;
            repeat (k,31) if (d & (1<<k)) ni = min(ni, and_skip[i][k]);
            int32_t x = 0x7fffffff;
            repeat_from (j,i,ni) {
                x = min(x, xor_acc[r] ^ xor_acc[j+1]);
            }
            m = max(m, d -(ll) x);
            d &= a[ni];
            i = ni;
        }
        // output
        printf("%lld\n", m);
    }
    return 0;
}
```
