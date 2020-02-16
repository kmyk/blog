---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-074-c/
  - /blog/2017/05/20/arc-074-c/
date: "2017-05-20T22:32:36+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc074/tasks/arc074_a" ]
---

# AtCoder Regular Contest 074: C - Chocolate Bar

チャレンジ失敗をした。

## solution

分け方は 大きく分けて $4$通り。$O(H + W)$。

$3$分割する場合はちょうどやり、$2$分割を$2$回する場合は最初の分割を総当たりし次は真ん中で。

図:

```
+----+-----+-----+
|    |     |     |
|    |     |     |
|    |     |     |
|    |     |     |
|    |     |     |
+----+-----+-----+
```

```
+----+-----------+
|    |           |
|    |           |
|    +-----------+
|    |           |
|    |           |
+----+-----------+
```

## implementation

``` c++
#include <cstdio>
#include <algorithm>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

constexpr ll inf = ll(1e18)+9;
int main() {
    // input
    ll h, w; scanf("%lld%lld", &h, &w);
    auto maxdiff = [&](ll ah, ll aw, ll bh, ll bw, ll ch, ll cw) {
        assert (0 <= ah and ah <= h);
        assert (0 <= bh and bh <= h);
        assert (0 <= ch and ch <= h);
        assert (0 <= aw and aw <= w);
        assert (0 <= bw and bw <= w);
        assert (0 <= cw and cw <= w);
        ll as = ah * aw;
        ll bs = bh * bw;
        ll cs = ch * cw;
        assert (as + bs + cs == h * w);
        return max(abs(as - bs), max(abs(bs - cs), abs(cs - as)));
    };
    // solve
    ll result = inf;
    { // // hr, hr
        ll ah = h / 3;
        ll bh = (h - ah) / 2;
        ll ch = h - ah - bh;
        setmin(result, maxdiff(ah, w, bh, w, ch, w));
    }
    { // // vr, vr
        ll aw = w / 3;
        ll bw = (w - aw) / 2;
        ll cw = w - aw - bw;
        setmin(result, maxdiff(h, aw, h, bw, h, cw));
    }
    { // // vr, hr
        ll ah = h;
        repeat_from (aw,0,w+1) {
            ll bw = w - aw;
            ll cw = w - aw;
            ll bh = h / 2;
            ll ch = h - bh;
            setmin(result, maxdiff(ah, aw, bh, bw, ch, cw));
        }
    }
    { // // hr, vr
        ll aw = w;
        repeat_from (ah,0,h+1) {
            ll bh = h - ah;
            ll ch = h - ah;
            ll bw = w / 2;
            ll cw = w - bw;
            setmin(result, maxdiff(ah, aw, bh, bw, ch, cw));
        }
    }
    // output
    printf("%lld\n", result);
    return 0;
}
```
