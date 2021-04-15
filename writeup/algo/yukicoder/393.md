---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/393/
  - /blog/2016/10/21/yuki-393/
date: "2016-10-21T15:40:59+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp", "greedy" ]
"target_url": [ "http://yukicoder.me/problems/no/393" ]
---

# Yukicoder No.393 2本の竹

諸々のやりたいこととその期限が被ってしまってとても忙しい。
競プロは息抜き。

## solution

貪欲 + DPで境界の確認。$O(m \min \\{ n_1, n_2 \\})$を$d$回。

竹が$1$本なら単純な貪欲で求まる。
$2$本の竹を繋げた竹に関しても同様に貪欲にすればほとんど十分。
ただしその$2$本の竹の継ぎ目を跨ぐような切断の仕方を回避できないようなら、貪欲の結果から$-1$する。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    int dataset; cin >> dataset;
    while (dataset --) {
        // input
        int n1, n2, m; cin >> n1 >> n2 >> m;
        vector<int> a(m); repeat (i,m) cin >> a[i];
        // roughly estimate
        whole(sort, a);
        int acc = 0;
        int cnt = 0;
        while (cnt < m and acc + a[cnt] <= n1 + n2) {
            acc += a[cnt];
            ++ cnt;
        }
        // check the boundary
        vector<bool> dp(n1+1);
        dp[0] = true;
        repeat (j, cnt) {
            repeat_reverse (i, n1) if (dp[i]) {
                if (i + a[j] < n1+1) {
                    dp[i + a[j]] = true;
                }
            }
        }
        int last = n1;
        while (not dp[last]) -- last;
        bool found = (acc - last <= n2);
        // output
        cout << (cnt - not found) << endl;
    }
    return 0;
}
```
