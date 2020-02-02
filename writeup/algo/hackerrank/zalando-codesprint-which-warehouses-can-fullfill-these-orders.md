---
layout: post
alias: "/blog/2016/06/05/hackerrank-zalando-codesprint-which-warehouses-can-fullfill-these-orders/"
title: "HackerRank Zalando CodeSprint: Which Warehouses Can Fulfill These Orders?"
date: 2016-06-05T19:17:48+09:00
tags: [ "competitive", "writeup", "hackerrank", "exhaustive-search" ]
"target_url": [ "https://www.hackerrank.com/contests/zalando-codesprint/challenges/which-warehouses-can-fullfill-these-orders" ]
---

## problem

商品が$P$種類ある。
倉庫が$W$個あって、それぞれの商品を$W\_{i,j}$個保管している。
注文が$B$個あって、それぞれの商品を$B_j$個要求する。
それぞれの注文に関し、それを満たすためにいくつかの倉庫を訪れて商品を集める。
このとき訪れるべき倉庫の数の最小値を答えよ。
ただしそれぞれの注文は独立である。

## solution

Exhaustive search about the visited warehouses. $O(2^W BP)$.

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int nw, nb, p; cin >> nw >> nb >> p;
    vector<vector<int> > w(nw, vector<int>(p)); repeat (i,nw) repeat (j,p) cin >> w[i][j];
    while (nb --) {
        vector<int> b(p); repeat (i,p) cin >> b[i];
        int ans = nw+1;
        repeat (s,1<<nw) {
            if (ans <= __builtin_popcount(s)) continue;
            vector<ll> acc(p);
            repeat (i,nw) if (s & (1<<i)) {
                repeat (j,p) {
                    acc[j] += w[i][j];
                }
            }
            bool fulfilled = true;
            repeat (j,p) {
                if (acc[j] < b[j]) {
                    fulfilled = false;
                    break;
                }
            }
            if (fulfilled) {
                ans = __builtin_popcount(s);
            }
        }
        cout << (ans == nw+1 ? -1 : ans) << endl;
    }
    return 0;
}
```
