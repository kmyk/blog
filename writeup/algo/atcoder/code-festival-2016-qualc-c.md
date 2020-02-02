---
layout: post
alias: "/blog/2016/10/23/code-festival-2016-qualc-c/"
date: "2016-10-23T23:00:14+09:00"
title: "CODE FESTIVAL 2016 qual C: C - 二人のアルピニスト / Two Alpinists"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2016-qualc/tasks/codefestival_2016_qualC_c" ]
---

矛盾する入力を失念しており$2$WA。ペナなしなので救われた。

## solution

$O(N)$。

入力に矛盾がないとする。
山の高さの記録が変化した点の山の高さはちょうどその値である。
そうでない点に関して、ふたりの記録の最小値より小さい範囲で自由に動かして記録に矛盾しない。
動かせる山$i_1, i_2, \dots, i_k$として、$\mathrm{ans} = \Pi \min \\{ t\_{i_j}, a\_{i_j} \\}$。

矛盾がないことは確認する必要がある。
ふたりの主張する最も高い山の高さが一致し、そのような山の位置が矛盾しない、が必要十分である。

## implementation

``` c++
#include <iostream>
#include <algorithm>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
const int mod = 1e9+7;
int main() {
    int n; cin >> n;
    vector<int> t(n); repeat (i,n) cin >> t[i];
    vector<int> a(n); repeat (i,n) cin >> a[i];
    vector<bool> fixed(n);
    fixed[0] = fixed[n-1] = true;
    repeat (i,n-1) if (t[i] < t[i+1]) fixed[i+1] = true;
    repeat (i,n-1) if (a[i] > a[i+1]) fixed[i  ] = true;
    ll acc = 1;
    repeat (i,n) if (not fixed[i]) acc = acc * min(t[i], a[i]) % mod;
    int highest = *whole(max_element, a);
    if (highest != t[n-1]) {
        acc = 0;
    } else {
        int i = whole(find, t, highest) - t.begin();
        int j = n - (find(a.rbegin(), a.rend(), highest) - a.rbegin()) - 1;
        if (j < i) acc = 0;
    }
    cout << acc << endl;
    return 0;
}
```
