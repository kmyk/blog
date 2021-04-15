---
redirect_from:
layout: post
date: 2018-07-10T13:03:00+09:00
tags: [ "competitive", "writeup", "icpc", "two-pointers-technique" ]
"target_url": [ "http://icpc.iisf.or.jp/past-icpc/domestic2018/contest/all_ja.html", "http://icpc.iisf.or.jp/past-icpc/domestic2018/judgedata/C/" ]
---

# ACM-ICPC 2018 国内予選: C. 超高層ビル「みなとハルカス」

## problem

<span>$$\sum_{i \in [l, r)} i = b$$</span>を満たす$l, r$であって$r - l$が最大となるものを求めよ。

## solution

とりあえず愚直解を考えるとしゃくとり法で、実装してみると間に合う。でも$O(b)$。
素数$999999937$のときが最悪ケースで$l = 499999968, \; r - l = 2$が答え。

計算量が小さい解としては$O(\sqrt{b} \log b)$。
$r - l$の上限は$\sqrt{2b}$程度なので、$r - l$を先に固定してから$l$を二分探索する。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i,n) for (int i = 0; (i) < (n); ++(i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
int main() {
    while (true) {
        int b; cin >> b;
        if (b == 0) break;
        cerr << "b = " << b << endl;
        int l = 1, r = 1;
        int acc = 0;
        while (true) {
            while (acc < b) acc += r ++;
            if (acc == b) break;
            while (acc > b) acc -= l ++;
            if (acc == b) break;
        }
        cout << l << ' ' << r - l << endl;
        cerr << l << ' ' << r - l << endl;
    }
    return 0;
}
```
