---
layout: post
alias: "/blog/2016/11/06/arc-063-d/"
date: "2016-11-06T22:48:18+09:00"
title: "AtCoder Regular Contest 063: D - 高橋君と見えざる手 / An Invisible Hand"
tags: [ "competitive", "wirteup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc063/tasks/arc063_b" ]
---

誤読しやすい(した)など嫌らしい問題文だった。

## solution

最大利益を上げられる$2$点を列挙しその個数を答える。$\min$演算に関して累積和を取れば$O(N)$。

まず$2$点間のリンゴひとつあたり利益の最大値$p(A) = \max \\{ A_j - A_i \mid i \lt j \\}$としよう。
特に制約がないため、全体としては$\lfloor\frac{T}{2}\rfloor \cdot p(A)$が利益。

$T$は無視できる。
$\lfloor\frac{T}{2}\rfloor$の部分は$A$によらず固定なので、単に$p(A') \lt p(A)$な$A'$を作るコストのみが問題であるため。
$T \ge 2$であることと合わせて、完全に無視してしまってよい。

$A_i$にはdistinct制約があり、これが効く。
$p(A) = A_j - A_i$な組$(i, j)$は複数個存在しうるが、この制約により互いに独立であることが言える。
つまりそのような組を全て集めてきて$\\{ (i_1, j_1), (i_2, j_2), \dots, (i_n, j_n) \\}$とすると、$i_1, i_2, \dots, i_n, j_1, j_2, \dots, j_n$は相異なる。
これは簡単に示せる。
よってそのような組の数が答えであるコストそのものになる。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
const int inf = 1e9+7;
int main() {
    int n, t; cin >> n >> t;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    vector<int> minacc(n+1); minacc[0] = inf; repeat (i,n) minacc[i+1] = min(minacc[i], a[i]);
    auto profit = [&](int i) { return a[i] - minacc[i+1]; };
    int max_profit = -1, cnt = 0;
    repeat (i,n) {
        if (max_profit < profit(i)) {
            max_profit = profit(i);
            cnt = 1;
        } else if (max_profit == profit(i)) {
            cnt += 1;
        }
    }
    cout << cnt << endl;
    return 0;
}
```
