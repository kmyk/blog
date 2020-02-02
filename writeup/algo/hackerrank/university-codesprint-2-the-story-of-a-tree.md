---
layout: post
alias: "/blog/2017/02/22/hackerrank-university-codesprint-2-the-story-of-a-tree/"
date: "2017-02-22T23:44:13+09:00"
title: "HackerRank University CodeSprint 2: The Story of a Tree"
tags: [ "competitive", "writeup", "hackerrank", "codesprint", "university-codesprint", "tree", "imos-method" ]
"target_url": [ "https://www.hackerrank.com/contests/university-codesprint-2/challenges/the-story-of-a-tree" ]
---

## problem

木、その隣接する頂点の順序対の列$(u_1, v_1), \dots, (u_g, v_g)$$、整数$k$が与えられる。
木の頂点を等確率でひとつ選んで根とするとき、$parent(v_i) = u_i$となるような$i$の数が$k$以上になる確率を答えよ。

## solution

木の上でのimos法。$O(N + G)$ for each query。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <functional>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
int gcd(int a, int b) { while (a) { b %= a; swap(a, b); } return b; }
int main() {
    int query; cin >> query;
    while (query --) {
        int n; cin >> n;
        vector<vector<int> > g(n);
        repeat (i,n-1) {
            int u, v; cin >> u >> v; -- u; -- v;
            g[u].push_back(v);
            g[v].push_back(u);
        }
        const int root = 0;
        vector<int> parent(n, -1); {
            function<void (int)> go = [&](int i) {
                for (int j : g[i]) if (j != parent[i]) {
                    parent[j] = i;
                    go(j);
                }
            };
            go(root);
        }
        int guess, k; cin >> guess >> k;
        vector<int> imos(n);
        while (guess --) {
            int u, v; cin >> u >> v; -- u; -- v;
            if (parent[v] == u) { // Alice's guess is true when root is 0
                imos[root] += 1;
                imos[v] -= 1;
            } else if (parent[u] == v) {
                imos[u] += 1;
            } else {
                assert (false);
            }
        }
        int cnt = 0;
        function<void (int, int)> go = [&](int i, int acc) {
            acc += imos[i];
            if (acc >= k) ++ cnt;
            for (int j : g[i]) if (j != parent[i]) go(j, acc);
        };
        go(root, 0);
        int d = gcd(cnt, n);
        cout << cnt/d << "/" << n/d << endl;
    }
    return 0;
}
```
