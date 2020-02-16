---
layout: post
date: 2018-07-10T13:01:00+09:00
tags: [ "competitive", "writeup", "icpc" ]
"target_url": [ "http://icpc.iisf.or.jp/past-icpc/domestic2018/contest/all_ja.html", "http://icpc.iisf.or.jp/past-icpc/domestic2018/judgedata/A/" ]
---

# ACM-ICPC 2018 国内予選: A. 所得格差

## implementation

$\sum a_i \le 10^9$ なので `a[i] <= (double) sum_a / n` などとしても誤差なく通る。

``` c++
#include <bits/stdc++.h>
#define REP(i,n) for (int i = 0; (i) < (n); ++(i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
int main() {
    while (true) {
        int n; cin >> n;
        if (n == 0) break;
        vector<int> a(n);
        REP (i, n) cin >> a[i];
        ll sum_a = accumulate(ALL(a), 0ll);
        int cnt = 0;
        REP (i, n) {
            if (a[i] * n <= sum_a) {
                ++ cnt;
            }
        }
        cout << cnt << endl;
        cerr << cnt << endl;
    }
    return 0;
}
```
