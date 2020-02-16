---
layout: post
redirect_from:
  - /blog/2016/05/14/arc-053-c/
date: 2016-05-14T23:03:04+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc053/tasks/arc053_c" ]
---

# AtCoder Regular Contest 053 C - 魔法使い高橋君

貪欲は(他と比べて)得意という感がある。

## solution

sort。貪欲。$O(N \log N)$。

魔法を順番に並べる。
魔法の使用に関連する状態は温度のみであり、隣接する魔法を交換してもそれらふたつを使用した後の温度に変化はない。
よって貪欲が可能。

ふたつの魔法$x = (a_x, b_x), y = (a_y, b_y)$をこの順に使用するとする。
この使用の際に関連する有効な温度は$t + a_x, t + a_x - b_x + a_y$のみであり、交換してこれが小さくなるなら交換すべきである。
正確には、対$(\max \\{ a_x, a_x - b_x + a_y \\}, a_x)$が小さくなるように交換する。

使用後に温度が下がる魔法についてのみ考えるところから入ると、貪欲に気付きやすいだろう。
しかし、温度が下がる魔法と上がる魔法に関する場合分けは不要である。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
template <class T> bool setmax(T & l, T const & r) { if (not (l < r)) return false; l = r; return true; }
typedef long long ll;
using namespace std;
struct magic_t { ll a, b; };
int main() {
    int n; cin >> n;
    vector<magic_t> xs(n); repeat (i,n) cin >> xs[i].a >> xs[i].b;
    sort(xs.begin(), xs.end(), [](magic_t x, magic_t y) {
        return make_pair(max(x.a, x.a - x.b + y.a), x.a) < make_pair(max(y.a, y.a - y.b + x.a), y.a);
    });
    ll ans = 0;
    ll t = 0;
    repeat (i,n) {
        t += xs[i].a;
        setmax(ans, t);
        t -= xs[i].b;
    }
    cout << ans << endl;
    return 0;
}
```
