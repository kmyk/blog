---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-094-d/
  - /blog/2018/04/07/arc-094-d/
date: "2018-04-07T23:01:44+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc094/tasks/arc094_b" ]
---

# AtCoder Regular Contest 094: D - Worst Case

## solution

二分探索していい感じにする。$O(\log (AB))$。

$1$回目のコンテストで$1$位の人は$2$回目のコンテストでは$AB - 1$位としてよく、
$1$回目のコンテストで$2$位の人は$2$回目のコンテストでは$\lfloor \frac{AB - 1}{2} \rfloor$位としてよい。
一般に$1$回目のコンテストで$n$位の人は$2$回目のコンテストでは$f(n) = \lfloor \frac{AB - 1}{n} \rfloor$位。
$n$を十分な範囲で列挙すれば$O(AB)$の愚直解。

$f(n)$は$n$を増やしていくとあるところから$1$以下しか減らなくなる。
そのような最小の$n$は二分探索で求まる。
それより小さい$i$については$(i, f(i))$という形で$n$個ほぼ全て使え、それより大きい$i$については$(n, f(n)), (n + 1, f(n) - 1), \dots, (n + f(n) - 1, 1)$と合計でおよそ$f(n)$個使える。
$A, B$と被ると使えなくなることが面倒だが、いい感じにすれば通る。

## note

-   雰囲気で通した 2
-   想定解がかしこい。とりあえず$A = B$と仮定して考えてみるとかすればよかったのだろうか

## implementation

``` c++
#include <cassert>
#include <iostream>
using ll = long long;
using namespace std;

template <typename UnaryPredicate>
int64_t binsearch(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;  // avoid overflow
        (p(m) ? r : l) = m;
    }
    return r;
}

ll solve(ll a, ll b) {
    ll dense = binsearch(1, a * b + 1, [&](ll i) {
        long double x = (a * b - 1) /(long double) i;
        long double y = (a * b - 1) /(long double) (i + 1);
        return x - y <= 1;
    });
    ll acc = 0;
    acc += dense - 1;
    acc += (a * b - 1) / dense;
    if (min(a, b) <= dense and
        min(a, b) <= (a * b - 1) / dense) {
        acc -= 1;
    }
    return acc;
}

int main() {
    int q; cin >> q;
    while (q --) {
        int a, b; cin >> a >> b;
        ll answer = solve(a, b);
        cout << answer << endl;
    }
    return 0;
}
```
