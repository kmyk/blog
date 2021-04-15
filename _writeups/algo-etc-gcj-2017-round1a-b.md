---
layout: post
redirect_from:
  - /writeup/algo/etc/gcj-2017-round1a-b/
  - /blog/2017/04/23/gcj-2017-round1a-b/
date: "2017-04-23T01:08:36+09:00"
tags: [ "competitive", "writeup", "gcj" ]
"target_url": [ "https://code.google.com/codejam/contest/5304486/dashboard#s=p1" ]
---

# Google Code Jam 2017 Round 1A: B. Ratatouille

問題文が難しすぎる。嫌い。

## problem

$N$種類の食材がそれぞれ$P$パッケージずつあり、それぞれ$Q\_{i,j}$グラム含む。
ratatouilleを$1$個作るのには食材$i$がそれぞれ$0.9R\_i \sim 1.1R\_i$グラム必要である。
$N$種類の食材からそれぞれ$1$パッケージずつ選び、整数$k$を決め、食材を過不足なく使って$k$個のratatouilleを消費すれば、$1$個のkitができる。
作るkitの数を最大化せよ。
ratatouilleの数ではないことに注意。

## solution

区間に直して整列して見ていく。$O(NP \log {NP})$。

各$Q\_{i,j}$から、$k \in [L, R)$と$k$個のratatouilleを作るのに$Q\_{i,j}$を使えることが同値になるように区間$[L\_{i,j}, R\_{i,j})$を作る。
$L\_{i,j}$を食材$i$の追加クエリ、$R\_{i,j}$を食材$i$の削除クエリとして見て、これらをその値の順に見ていく。
個数$k$を増やしていきながら処理していって、全ての食材が同時にひとつ以上使えるならば貪欲に使えばよい。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <queue>
#include <tuple>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;
int solve(int n, int p, vector<int> const & required, vector<vector<int> > const & quantity) {
    auto low = vectors(n, p, int());
    auto high = vectors(n, p, int()); // [l, r]
    repeat (i,n) {
        repeat (j,p) {
            const int r = required[i];
            const int q = quantity[i][j];
            int & lo = low[i][j];
            int & hi = high[i][j];
            lo = (10*q + 11*r-1) / (11*r);
            hi = 10*q / ( 9*r);
            if (lo <= hi) {
                constexpr double eps = 1e-8;
                assert (0.9*r*lo < eps + q and q < eps + 1.1*r*lo);
                assert (0.9*r*hi < eps + q and q < eps + 1.1*r*hi);
                assert (not (0.9*r*(lo-1) < eps + q and q < eps + 1.1*r*(lo-1)));
                assert (not (0.9*r*(hi+1) < eps + q and q < eps + 1.1*r*(hi+1)));
            }
        }
    }
    reversed_priority_queue<tuple<int, bool, int> > que;
    repeat (i,n) {
        repeat (j,p) {
            if (low[i][j] <= high[i][j]) {
                que.emplace(low[i][j], false, i);
                que.emplace(high[i][j], true, i);
            }
        }
    }
    vector<int> used(n);
    vector<int> remaining(n);
    int result = 0;
    while (not que.empty()) {
        int cur_time; bool is_pop; int i; tie(cur_time, is_pop, i) = que.top(); que.pop();
        if (is_pop) {
            if (used[i]) {
                -- used[i];
            } else {
                assert (remaining[i]);
                -- remaining[i];
            }
        } else {
            ++ remaining[i];
            if (remaining[i] == 1) {
                if (*whole(min_element, remaining) >= 1) {
                    repeat (j,n) remaining[j] -= 1;
                    repeat (j,n) used[j] += 1;
                    result += 1;
                }
            }
        }
    }
    return result;
}
int main() {
    int t; scanf("%d", &t);
    repeat (x,t) {
        int n, p; scanf("%d%d", &n, &p);
        vector<int> r(n); repeat (i,n) scanf("%d", &r[i]);
        auto q = vectors(n, p, int()); repeat (i,n) repeat (j,p) scanf("%d", &q[i][j]);
        int result = solve(n, p, r, q);
        printf("Case #%d: %d\n", x+1, result);
    }
    return 0;
}
```
