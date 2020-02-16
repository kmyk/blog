---
layout: post
alias: "/blog/2017/10/03/arc-072-c/"
date: "2017-10-03T04:22:36+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc072/tasks/arc072_a" ]
---

# AtCoder Regular Contest 072: C - Sequence

## solution

貪欲っぽい。$O(N)$。
$a\_0$の移動先を$a\_0, +1, -1$の$3$つから全て試す。
$a\_n$まで決定したとき$a\_{n+1}$は総和が条件を満たすような最小量だけ動かせばよい。
つまり総和はそのままか$+1, -1$になる。

これで十分なのは、$i \lt j$な$a\_i$まで見て制約違反がなく$a\_j$で違反するとき、$a\_i$を動かして解消するのと$a\_j$を動かして解消するのはどちらを動かしても移動量は同じであるため。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }
constexpr ll inf = ll(1e18)+9;

ll solve(vector<ll> const & a, ll initial) {
    int n = a.size();
    ll cnt = llabs(initial);
    ll acc = a[0] + initial;
    repeat (i,n-1) {
        ll nacc = acc + a[i + 1];
        if (acc > 0 and nacc >= 0) {
            cnt += nacc + 1;
            nacc = -1;
        }
        if (acc < 0 and nacc <= 0) {
            cnt += - nacc + 1;
            nacc = 1;
        }
        acc = nacc;
    }
    return cnt;
}

int main() {
    int n; scanf("%d", &n);
    vector<ll> a(n); repeat (i,n) scanf("%lld", &a[i]);
    ll result = inf;
    if (a[0] != 0) setmin(result, solve(a, 0));
    if (a[0] >= 0) setmin(result, solve(a, - a[0] - 1));
    if (a[0] <= 0) setmin(result, solve(a, - a[0] + 1));
    printf("%lld\n", result);
    return 0;
}
```
