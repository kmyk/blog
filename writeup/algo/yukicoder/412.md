---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/412/
  - /blog/2016/09/29/yuki-412/
date: "2016-09-29T23:04:55+09:00"
tags: [ "competitive", "writeup", "yukicoder", "case-analysis", "combination" ]
"target_url": [ "http://yukicoder.me/problems/770" ]
---

# Yukicoder No.412 花火大会

想定解がDPだったので驚いた。

## solution

家族$B, C, D$の要求は入れ子になっているので、レジャーシートを以下のように分類できる。

-   $e_0$: $0$種の家族の要求を満たす。
-   $e_1$: $1$種の家族の要求を満たす。
-   $e_2$: $2$種の家族の要求を満たす。
-   $e_3$: $3$種の家族の要求を満たす。

また、その要求の満たし方は以下のように分類できる。

-   $e_1$, $e_2$, $e_3$を使って要求を満たす。
-   $e_1$, $e_3 \times 2$を使って要求を満たす。
-   $e_2 \times 2$, $e_3$を使って要求を満たす。
-   $e_2$, $e_3 \times 2$を使って要求を満たす。
-   $e_3 \times 3$を使って要求を満たす。

それぞれ計算して足し合わせればよい。
例えば$2$番目の場合であれば$2^{e_0}(2^{e_1}-1)(2^{e_3}-1-e_3)$通りである。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
ll p(int n) { return 1ll << n; }
ll c(int n, int r) {
    ll acc = 1;
    repeat (i,r) acc *= n-i;
    repeat (i,r) acc /= i+1;
    return acc;
}
ll f(int n, int r) {
    ll acc = p(n);
    repeat (i,r) acc -= c(n,i);
    return acc;
}
int main() {
    // input
    int b, c, d; cin >> b >> c >> d;
    int n; cin >> n;
    vector<int> es(n); repeat (i,n) cin >> es[i];
    // compute
    array<int,4> e = {};
    repeat (i,n) {
        int cnt = 0;
        cnt += int(b <= es[i]);
        cnt += int(c <= es[i]);
        cnt += int(d <= es[i]);
        e[cnt] += 1;
    }
    ll ans = 0;
    ans += p(e[0]) * f(e[1], 1) * f(e[2], 1) * f(e[3], 1);
    ans += p(e[0]) * f(e[1], 1)              * f(e[3], 2);
    ans += p(e[0]) *              f(e[2], 2) * f(e[3], 1);
    ans += p(e[0]) *                e[2]     * f(e[3], 2);
    ans += p(e[0]) *                           f(e[3], 3);
    cout << ans << endl;
    return 0;
}
```
