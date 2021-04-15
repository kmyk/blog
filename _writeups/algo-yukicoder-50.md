---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/50/
  - /blog/2016/11/15/yuki-50/
date: "2016-11-15T18:06:59+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp", "bit-dp", "greedy" ]
"target_url": [ "http://yukicoder.me/problems/no/50" ]
---

# Yukicoder No.50 おもちゃ箱

## solution

DP。箱は大きい方から貪欲に使って$\mathrm{dp}: (M+1) \times 2^N \to 2$。$O(M4^N)$。

箱は大きい方から$n$個使えばよいというのは重要で、この仮定がないと$\mathrm{dp}: 2^M \times 2^N \to 2$が必要になってしまう。(それでも間に合わないことはないらしいが。)

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
template <typename T, typename X> auto vectors(T a, X x) { return vector<T>(x, a); }
template <typename T, typename X, typename Y, typename... Zs> auto vectors(T a, X x, Y y, Zs... zs) { auto cont = vectors(a, y, zs...); return vector<decltype(cont)>(x, cont); }
int main() {
    // input
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    int m; cin >> m;
    vector<int> b(m); repeat (j,m) cin >> b[j];
    // compute
    vector<int> sum(1<<n); repeat_from (s,1,1<<n) sum[s] = sum[s&(s-1)] + a[__builtin_ctz(s)]; // http://www.slideshare.net/KMC_JP/slide-www
    sort(b.rbegin(), b.rend());
    vector<vector<bool> > dp = vectors(bool(), m+1, 1<<n);
    dp[0][0] = true;
    repeat (j,m) {
        repeat (k,1<<n) if (sum[k] <= b[j]) {
            repeat (s,1<<n) {
                if (dp[j][s]) dp[j+1][s|k] = true;
            }
        }
    }
    // output
    int ans = -1;
    repeat (j,m+1) {
        if (dp[j][(1<<n)-1]) {
            ans = j;
            break;
        }
    }
    cout << ans << endl;
    return 0;
}
```
