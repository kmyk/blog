---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/102/
  - /blog/2016/09/13/yuki-102/
date: "2016-09-13T23:18:32+09:00"
tags: [ "competitive", "writeup", "yukicoder", "game", "nim", "grandy" ]
"target_url": [ "http://yukicoder.me/problems/no/102" ]
---

# Yukicoder No.102 トランプを奪え

全体の最後の$1$枚を取った方が勝利する。
最後に相手の手札の半分(切り上げ)を奪うのでこれだけで勝ちが確定する。
よって、手札の概念が消え、ただのnimに帰着する。

全体の最後の$1$枚を取った方が勝利というのに気付いてなかったので、$O(\Pi_iN_i \cdot (\Sigma_iN_i)^2)$ぐらいのmemo化再帰でした。$N_i \le 13$なのでそれでも十分高速だった。
頭回ってなかった。

``` c++
#include <iostream>
#include <algorithm>
#include <vector>
#include <array>
#include <map>
#include <tuple>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }

const int win  = 1;
const int draw = 0;
const int lose = -1;
int solve(array<int,4> n, int a, int b) {
    whole(sort, n);
    static map<tuple<array<int,4>, int, int>, int> memo;
    auto key = make_tuple(n, a, b);
    if (memo.count(key)) return memo[key];
    int result = -2;
    repeat (i,4) {
        repeat_from (d, 1, min(3,n[i])+1) {
            n[i] -= d;
            int c = n[i] ? 0 : (b+1)/2;
            setmax(result, - solve(n, b-c, a+d+c));
            n[i] += d;
            if (result == win) return memo[key] = win;
        }
    }
    if (result == -2) {
        result = a > b ? win : a < b ? lose : draw;
    }
    return memo[key] = result;
}
int main() {
    array<int,4> n; cin >> n[0] >> n[1] >> n[2] >> n[3];
    int ans = solve(n, 0, 0);
    cout << (ans == win ? "Taro" : ans == lose ? "Jiro" : "Draw") << endl;
    return 0;
}
```
