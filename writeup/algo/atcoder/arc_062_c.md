---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_062_c/
  - /writeup/algo/atcoder/arc-062-c/
  - /blog/2016/10/15/arc-062-c/
date: "2016-10-15T23:54:54+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc062/tasks/arc062_a" ]
---

# AtCoder Regular Contest 062 C - AtCoDeerくんと選挙速報 / AtCoDeer and Election Report

ICPCアジア地区予選のため、つくばのホテルで解いた。

## problem

$a_i, b_i$ for $i \lt n$が与えられる。
$a_id_i \le a\_{i+1}d\_{i+1} \land b_id_i \le b\_{i+1}d\_{i+1}$を満たす列を$d_i$ for $i \lt n$としたとき、$a\_{n-1}d\_{n-1} + b\_{n-1}d\_{n-1}$の最小値を答えよ。

## solution

再帰的に$d_i$を計算すればよい。$O(N)$。

式は以下。

-   $d_0 = 1$
-   $d\_{i+1} = \min \\{ d \mid a_id_i \le a\_{i+1}d \land b_id_i \le b\_{i+1}d \\}$

$d$を$0$からincrementしていくと間に合わないが、$a_id_i \le a\_{i+1}d$を変形して$\frac{a_id_i}{a\_{i+1}} \le d$であることを使えば各stepを$O(1)$で行える。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int n; cin >> n;
    vector<int> as(n), bs(n); repeat (i,n) cin >> as[i] >> bs[i];
    ll a = as[0];
    ll b = bs[0];
    repeat_from (i,1,n) {
        ll d = max(a / as[i], b / bs[i]);
        while (not (a <= as[i] * d and b <= bs[i] * d)) d += 1;
        a = as[i] * d;
        b = bs[i] * d;
    }
    cout << a + b << endl;
    return 0;
}
```
