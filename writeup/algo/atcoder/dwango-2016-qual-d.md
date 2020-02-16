---
layout: post
redirect_from:
  - /blog/2016/01/24/dwango-2016-qual-d/
date: 2016-01-24T00:40:35+09:00
tags: [ "competitive", "writeup", "atcoder", "dwango" ]
---

# 第2回 ドワンゴからの挑戦状 予選 D - 庭園

直線引いて分けるの思い付かなくても、気合いでやればできる。

## [D - 庭園](https://beta.atcoder.jp/contests/dwango2016-prelims/tasks/dwango2016qual_d)

### 解説

やる。$O(HW(H+W))$。
ふたつの軸並行な長方形領域で交差しないものは、$y$軸か$x$軸に並行な直線を間に引くことができることを使うと楽になる。

図示すると、以下のようにふたつ領域`A`,`B`があったとき、

``` plain
AAAAAA
AAAAAA     BBB
AAAAAA     BBB
           BBB
           BBB
```

以下のように直線で区切れる、ということ。

``` plain
AAAAAA  |
AAAAAA  |  BBB
AAAAAA  |  BBB
        |  BBB
        |  BBB
```

$y$方向に$[l,r)$を使ってできるような区間に関するその和の最大値$m\_{l,r} = \max\_{a,b} \\{ (y,x) \mid l \le y \lt r, a \le x \lt b \\}$は$O(H^2W)$で計算できる。
領域を右に伸ばしていってその和が負になったら左端をリセットする。
当然、累積和を用いて任意の領域$R$に関して$O(1)$で出せるようにしておく。

$y = k$という直線を引いて領域$A$,$B$を区切ることができるとき、そのような領域に関する和の最大値${\rm ans}$は、$m_y^\gets = \max \\{ m\_{l,r} \mid r \le y \\}$および$m_y^\to = \max \\{ m\_{l,r} \mid y \le l \\}$を用いて、${\rm ans} = \max \\{ m_y^\gets + m_y^\to \\}$として$O(H^2W)$で計算できる。

$x = k$という直線で区切った場合も同様に行う。

### 実装

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
const ll INF = 1e18;
ll foo(vector<vector<ll> > const & b) {
    int h = b.size(), w = b.front().size();
    vector<vector<ll> > acc(w, vector<ll>(h+1));
    repeat (x,w) repeat (y,h) acc[x][y+1] = acc[x][y] + b[y][x];
    vector<vector<ll> > mx(h, vector<ll>(h+1, - INF)); // mx[l][r], [l,r)
    repeat (r,h+1) repeat (l,r) {
        ll a = 0;
        repeat (x,w) {
            a = max(a, 0ll) + (acc[x][r] - acc[x][l]);
            mx[l][r] = max(mx[l][r], a);
        }
    }
    vector<ll> mxl(h, - INF), mxr(h+1, - INF);
    repeat (r,h+1) repeat (l,r) {
        repeat (y,h+1) {
            if (r <= y) mxr[y] = max(mxr[y], mx[l][r]);
            if (y <= l) mxl[y] = max(mxl[y], mx[l][r]);
        }
    }
    ll ans = - INF;
    repeat (y,h-1) ans = max(ans, mxr[y+1] + mxl[y+1]);
    return ans;
}
int main() {
    int h, w; cin >> h >> w;
    vector<vector<ll> > b(h, vector<ll>(w));
    vector<vector<ll> > a(w, vector<ll>(h));
    repeat (y,h) repeat (x,w) {
        ll it; cin >> it;
        b[y][x] = a[x][y] = it;
    }
    cout << max(foo(a), foo(b)) << endl;
    return 0;
}
```
