---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/524/
  - /blog/2017/06/02/yuki-524/
date: "2017-06-02T23:06:31+09:00"
tags: [ "competitive", "writeup", "yukicoder", "nim", "grundy" ]
"target_url": [ "http://yukicoder.me/problems/no/524" ]
---

# Yukicoder No.524 コイン

## solution

これはそのままちょうどnim。
排他的論理和でgrundy数$\sum\_{0 \le i \le n} i$を求めるだけとなる。
$O(N)$。

コンパイラ任せのSIMD並列では少し間に合わなかったので埋め込み。
試すと$N = k \times 10^8$の場合はgrundy数$N$らしい(あるいは$(k \times 10^8) - 1$のときに$0$)のでそのようにした。

## implementation

``` c++
#include <cstdio>
using ll = long long;
int main() {
    ll n; scanf("%lld", &n);
    ll g = n / 100000000 * 100000000;
    for (ll i = g+1; i <= n; ++ i) {
        g ^= i;
    }
    printf("%c\n", g ? 'O' : 'X');
    return 0;
}
```
