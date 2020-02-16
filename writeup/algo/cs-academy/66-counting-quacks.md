---
layout: post
alias: "/blog/2018/04/02/csa-66-counting-quacks/"
date: "2018-04-02T01:49:03+09:00"
tags: [ "competitive", "writeup", "csa", "eratosthenes-seive" ]
"target_url": [ "https://csacademy.com/contest/round-66/task/counting-quacks/statement/" ]
---

# CS Academy Round #66 (Div. 2 only): Counting Quacks

## solution

Eratosthenesの篩みたいにする。$O(N + T \log T)$。

## note

「計算量が意外な感じ」みたいな言及が流れてきたので解いた。あまり分からなかった。
でも同じ値の$X\_i$を潰さないと$O(NT)$に増えるのはちょっと面白さあるか。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

pair<int, int> solve(int n, int t, vector<int> const & x) {
    map<int, int> compressed;
    for (int x_i : x) compressed[x_i] += 1;
    vector<int> cnt(t + 1);
    for (auto it : compressed) {
        int x_i, k; tie(x_i, k) = it;
        for (int j = x_i; j <= t; j += x_i) {
            cnt[j] += k;
        }
    }
    int a = *max_element(ALL(cnt));
    int b = count(ALL(cnt), a);
    return { a, b };
}

int main() {
    int n, t; cin >> n >> t;
    vector<int> x(n); REP (i, n) cin >> x[i];
    int a, b; tie(a, b) = solve(n, t, x);
    cout << a << ' ' << b << endl;
    return 0;
}
```
