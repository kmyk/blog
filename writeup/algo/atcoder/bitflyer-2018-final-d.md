---
layout: post
date: 2018-07-02T20:13:41+09:00
tags: [ "competitive", "writeup", "atcoder", "codeflyer", "xor", "gaussian-elimination" ]
"target_url": [ "https://beta.atcoder.jp/contests/bitflyer2018-final-open/tasks/bitflyer2018_final_d" ]
---

# codeFlyer （bitFlyer Programming Contest）: D - 数列 XOR

## solution

$\mathbb{F}\_2$上のvectorの集合として基底が一致するか判定。$O(N^2)$。
xorがvector空間に繋がるのは典型。

まず観察。
自明に「隣接する要素に足し込むのが可能」であり、すぐに「隣接する要素のswapが可能」が言え、このふたつから「任意の要素を任意の異なる要素に足し込むのが可能」が言える。
さらに操作はすべて可逆なので「$B$の側を操作してもよい」。
なんとなく$A$にGaussの消去法をして、$B$のそれぞれの要素を判定できるか見ればよさそう。
しかし自分自身には足せないので例えば$A = (1, 1, 2)$から$B = (0, 0, 2)$は作れない。
このあたりで基底を等号で比較すればいい気がしてくるので、そのようにすると通る。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

vector<uint64_t> gaussian_elimination(vector<uint64_t> a) {
    int n = a.size();
    int rank = 0;
    for (uint64_t mask = 1; mask; mask <<= 1) {
        int pivot = rank;
        while (pivot < n and not (a[pivot] & mask)) ++ pivot;
        if (pivot >= n) continue;
        swap(a[rank], a[pivot]);
        REP (i, n) if (i != rank) {
            if (a[i] & mask) {
                a[i] ^= a[rank];
            }
        }
        ++ rank;
    }
    a.resize(rank);
    return a;
}

int main() {
    // input
    int n; cin >> n;
    vector<uint64_t> a(n), b(n);
    REP (i, n) cin >> a[i];
    REP (i, n) cin >> b[i];

    // solve
    a = gaussian_elimination(a);
    b = gaussian_elimination(b);
    bool answer = a == b;

    // output
    cout << (answer ? "Yes" : "No") << endl;
    return 0;
}
```
