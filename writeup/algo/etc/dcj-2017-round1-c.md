---
layout: post
alias: "/blog/2017/05/15/dcj-2017-round1-c/"
date: "2017-05-15T11:08:45+09:00"
title: "Google Code Jam Distributed Round 1 2017: C. weird_editor"
tags: [ "competitive", "writeup", "dcj", "distributed-code-jam", "repunit" ]
"target_url": [ "https://code.google.com/codejam/contest/8314486/dashboard#s=p2" ]
---

## solution

各区間ごとに個別の文字列として見て処理すると、その結果は文字列$9^{k\_9}8^{k\_8}7^{k\_7}6^{k\_6}5^{k\_5}4^{k\_4}3^{k\_3}2^{k\_2}1^{k\_1}0^{k\_0}$の形をしている。
実際には$0$は全体の文字列の末尾に動くが、後の処理で同じことになるのでこれでよい。
これは整数$k\_9, \dots, k\_0$とすれば高速に受け渡しできて、中央ノードで同様に再度処理すればよい。
長さ$N$とノード数$K$に対し$O(\frac{N}{K} + K)$。

## implementation

$K = 100$かつ$N \le 10^9$。今回$867$ms。定数として数字の種類$k = 10$が乗ってるからこれぐらいが妥当。
しかし`GetDigit(i)`の呼び出しは$0.11$usらしいので$\frac{N}{K} \le 10^7$回呼んだら固定で$1100$msかかるはずなのだけど、妙に速い。

``` c++
#include "message.h"
#include "weird_editor.h"
#include <cstdio>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using ll = long long;
using namespace std;

ll powmod(ll x, ll y, ll p) { // O(log y)
    assert (0 <= x and x < p);
    assert (0 <= y);
    ll z = 1;
    for (ll i = 1; i <= y; i <<= 1) {
        if (y & i) z = z * x % p;
        x = x * x % p;
    }
    return z;
}
ll repunit(ll n, ll p) {
    ll y = 0;
    ll x = 1;
    for (ll i = 1; i <= n; i <<= 1) {
        if (n & i) y = (y * powmod(10, i, p) % p + x) % p;
        x = (x * powmod(10, i, p) % p + x) % p;
    }
    return y;
}

constexpr ll mod = 1e9+7;
int main() {
    const int number_of_nodes = NumberOfNodes();
    const int my_node_id = MyNodeId();
    int n = GetNumberLength();
    { // on each node
        int l = (n *(ll)  my_node_id     ) / number_of_nodes;
        int r = (n *(ll) (my_node_id + 1)) / number_of_nodes;
        array<int, 10> cnt = {};
        repeat_from (i,l,r) {
            int d = GetDigit(i);
            assert (0 <= d and d <= 9);
            cnt[d] += 1;
            repeat_from (e,1,d) {
                cnt[0] += cnt[e];
                cnt[e] = 0;
            }
        }
        repeat (d,10) {
            PutInt(0, cnt[d]);
        }
        Send(0);
    }
    if (my_node_id == 0) { // sum up
        array<int, 10> cnt = {};
        repeat (node_id, number_of_nodes) {
            Receive(node_id);
            array<int, 10> ds;
            repeat (d,10) {
                ds[d] = GetInt(node_id);
            }
            repeat_reverse (d,10) if (ds[d]) {
                cnt[d] += ds[d];
                repeat_from (e,1,d) {
                    cnt[0] += cnt[e];
                    cnt[e] = 0;
                }
            }
        }
        ll result = 0;
        repeat_reverse (d,10) {
            result = result * powmod(10, cnt[d], mod) % mod;
            result = (result + d *(ll) repunit(cnt[d], mod) % mod) % mod;
        }
        printf("%lld\n", result);
    }
    return 0;
}
```
