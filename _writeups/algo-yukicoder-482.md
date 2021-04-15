---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/482/
  - /blog/2017/04/20/yuki-482/
date: "2017-04-20T04:03:34+09:00"
tags: [ "competitive", "writeup", "yukicoder", "sort" ]
"target_url": [ "http://yukicoder.me/problems/no/482" ]
---

# Yukicoder No.482 あなたの名は

overflowでWA。`-fsanitize=undefined` してても`scanf`の中の話は範囲外らしい。

## solution

整列するために必要なswapの最小回数を$t$として$(k - t) \ge 0 \land (k - t) \equiv 0 \pmod{2}$が答え。$O(N)$。

最小回数で整列させるのは貪欲にやればよい。
その後余った回数は$2$つずつ消費する。
置換の偶奇性により、その結果$1$つだけ余ってしまうようならどうやっても無理。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
int main() {
    int n; ll k; scanf("%d%lld", &n, &k);
    vector<int> d(n); repeat (i,n) { scanf("%d", &d[i]); -- d[i]; }
    vector<int> e(n); repeat (i,n) e[d[i]] = i;
    repeat (i,n) {
        if (d[i] != i) {
            int j = e[i];
            swap(d[i], d[j]);
            e[d[i]] = i;
            e[d[j]] = j;
            k -= 1;
        }
    }
    bool result = k >= 0 and k % 2 == 0;
    printf("%s\n", result ? "YES" : "NO");
    return 0;
}
```
