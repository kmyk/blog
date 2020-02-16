---
layout: post
alias: "/blog/2016/11/30/code-festival-2016-relay-g/"
date: "2016-11-30T01:33:28+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-relay-open/tasks/relay_g" ]
---

# CODE FESTIVAL 2016 Relay: G - 超能力 / Magician

## solution

愚直。操作ごとにその周辺で魔法を使ってみる。$O(Q)$。$A_i, B_i$番目のコップに移ってくる/出ていく両方の向きの魔法を見ることを忘れないよう注意。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    int n, q; cin >> n >> q;
    vector<bool> x(n), y(n);
    x[0] = true;
    y[1] = true;
    while (q --) {
        int a, b; cin >> a >> b; -- a; -- b;
        swap(x[a], x[b]);
        swap(y[a], y[b]);
        for (int i : { a-1, a, a+1, b-1, b, b+1 }) if (0 <= i and i < n and x[i]) {
            for (int j : { i-1, i+1 }) if (0 <= j and j < n) {
                y[j] = true;
            }
        }
    }
    int ans = 0;
    repeat (i,n) ans += x[i] or y[i];
    cout << ans << endl;
    return 0;
}
```
