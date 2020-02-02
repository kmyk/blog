---
layout: post
alias: "/blog/2017/05/15/dcj-2017-round1-d/"
date: "2017-05-15T11:08:47+09:00"
title: "Google Code Jam Distributed Round 1 2017: D. todd_and_steven"
tags: [ "competitive", "writeup", "dcj", "distributed-code-jam", "binary-search" ]
"target_url": [ "https://code.google.com/codejam/contest/8314486/dashboard#s=p3" ]
---

In progessな状態がscoreboard上でIncorrect扱いされるバグのせいで無駄な作業をしてしまった。

## solution

各ノードに整列後の列の上の区間$[l, r)$を割り当てる。
値からそれぞれの列$A\_o, A\_e$上でのindexを求めるのは二分探索でできる。
整列後の列$B$の$l$項目$B\_l$の値を求めるのは、上の二分探索を述語に使って再度の二分探索でできる。
$B\_l$が求まれば列$A\_o, A\_e$上のindexをそれぞれ再度求め、そこから単純に$r-l$個読めばよい。
長さ$N\_o,N\_e$と要素の最大値$A\_\mathrm{max}$とノード数$K$に対し$O(\frac{\log A\_\mathrm{max} \cdot (\log N\_o + \log N\_e)}{K} + K)$。

## implementation

distributedだとかまったく関係ない普通のにぶたんをバグらせて手間取っていた。

$K = 100$で$N\_o, N\_e \le 10^9$の制約で$1227$msだった。制限時間$4$secなことを考えると他と同じくらいらしい。

``` c++
#include "message.h"
#include "todd_and_steven.h"
#include <cstdio>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;

constexpr ll inf = ll(1e18)+9;
template <typename F>
ll GetLowerBoundIndexForValue(ll value, int n, F GetValue) {
    ll l = -1, r = n; // (l, r]
    while (r - l >= 2) {
        ll m = (l + r) / 2;
        ll result = m < n ? GetValue(m) : inf;
        (result >= value ? r : l) = m;
    }
    return r;
}
ll GetLowerBoundValueForIndex(ll index, int todd_length, int steven_length) {
    ll l = -1, r = 5ll*1e9; // (l, r]
    while (r - l >= 2) {
        ll m = (l + r) / 2;
        ll j =
            GetLowerBoundIndexForValue(m, todd_length, GetToddValue)
            + GetLowerBoundIndexForValue(m, steven_length, GetStevenValue);
        (j >= index ? r : l) = m;
    }
    return r;
}

constexpr ll mod = 1e9+7;
int main() {
    const int number_of_nodes = NumberOfNodes();
    const int my_node_id = MyNodeId();
    int todd_length = GetToddLength();
    int steven_length = GetStevenLength();
    ll n = todd_length + steven_length;
    { // on each node
        ll l = (n *  my_node_id     ) / number_of_nodes;
        ll r = (n * (my_node_id + 1)) / number_of_nodes;
        ll value = GetLowerBoundValueForIndex(l, todd_length, steven_length);
        ll todd_index = GetLowerBoundIndexForValue(value, todd_length, GetToddValue);
        ll steven_index = GetLowerBoundIndexForValue(value, steven_length, GetStevenValue);
        ll todd_value, steven_value;
        auto update_todd_value = [&]() {
            todd_value = todd_index < todd_length ? GetToddValue(todd_index) : inf;
            ++ todd_index;
        };
        auto update_steven_value = [&]() {
            steven_value = steven_index < steven_length ? GetStevenValue(steven_index) : inf;
            ++ steven_index;
        };
        update_todd_value();
        update_steven_value();
        ll result = 0;
        repeat_from (i,l,r) {
            if (todd_value < steven_value) {
                result += (todd_value ^ i);
                update_todd_value();
            } else {
                result += (steven_value ^ i);
                update_steven_value();
            }
        }
        result %= mod;
        PutLL(0, result);
        Send(0);
    }
    if (my_node_id == 0) { // sum up
        ll result = 0;
        repeat (node_id, number_of_nodes) {
            Receive(node_id);
            result += GetLL(node_id);
        }
        result %= mod;
        printf("%lld\n", result);
    }
    return 0;
}
```
