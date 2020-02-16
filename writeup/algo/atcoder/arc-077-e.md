---
layout: post
redirect_from:
  - /blog/2017/07/20/arc-077-e/
date: "2017-07-20T03:11:58+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "imos" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc077/tasks/arc077_c" ]
---

# AtCoder Regular Contest 077: E - guruguru

## solution

($1$次元$1$次の)imos法が楽。あるいは端点を覚えておいてイベント列の処理のようにしても可能。$O(N + M)$。

切り替え$a\_i \to a\_{i + 1}$するとして、お気に入りの明るさが$x$のときにボタンを押す回数をいくつ減らせるか考える。これは$a\_i + 1 \le x \le a\_{i + 1}$のとき\$x - (a\_i + 1)$である。
切り替えごとにこれを求めて足し合わせれば$x$で減らせるボタンの数が求まるので、これがほぼ答えとなる。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;

int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    // solve
    ll total = 0;
    vector<ll> imos0(2 * m);
    vector<ll> imos1(2 * m);
    repeat (i, n - 1) {
        int l = a[i] - 1;
        int r = a[i + 1] - 1;
        if (r < l) r += m; // [l, r] on [0, 2n)
        total += r - l;
        if (r - l <= 1) continue;
        imos0[l + 2] += 1;
        imos0[r + 1] -= 1;
        imos1[r + 1] -= (r + 1) - (l + 2);
    }
    imos1[0] += imos0[0];
    repeat (i, 2 * m - 1) {
        imos0[i + 1] += imos0[i];
        imos1[i + 1] += imos1[i] + imos0[i + 1];
    }
    vector<ll> reward(m);
    repeat (i, m) reward[i] = imos1[i] + imos1[i + m];
    ll result = total - *whole(max_element, reward);
    // output
    printf("%lld\n", result);
    return 0;
}
```
