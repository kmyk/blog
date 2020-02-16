---
layout: post
redirect_from:
  - /blog/2017/07/23/agc-018-c/
date: "2017-07-23T23:18:15+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "flow", "minimum-cost-flow" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc018/tasks/agc018_c" ]
---

# AtCoder Grand Contest 018: C - Coins

橙になった。

ところでこれってけっこう一般的に使える最小費用流の加速法なのでは。

## solution

最小費用流。$V, E \ge 10^5$なので汎用的な方法では間に合わないのでグラフの形を使ってad-hocにやる。たぶん$O((X + Y + Z)\log{(X + Y + Z)})$。

流路は下図のような感じ。負の重みは簡単に消去できる。

```
-a/b- : capacity = a, cost = b

    ----X/0---- X ----?/(-A)-
   /                         \
src ----Y/0---- Y ----?/(-B)- i ----1/0---- dst
   \                         /
    ----Z/0---- Z ----?/(-C)-
```

これを高速に計算したい。
最小性を気にせず流した後、容量正の負閉路があればそこに流して消すことを繰り返して解を得るアルゴリズムが存在した。
これをグラフの形を利用して高速に書き直す。
つまり$i$が$X$かつ$j$が$Y$に流れていて$B\_i - A\_i + A\_j - B\_j$なものがあれば、これを交換する。
$i$が$X$かつ$j$が$Y$かつ$k$が$Z$でも同様。
これは優先度付きqueueとかでいい感じにできて間に合う。

## implementation

``` c++
#include <cstdio>
#include <queue>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

int main() {
    int x, y, z; scanf("%d%d%d", &x, &y, &z);
    const int n = x + y + z;
    vector<array<int, 3> > a(n);
    repeat (i, n) {
        scanf("%d%d%d", &a[i][0], &a[i][1], &a[i][2]);
    }
    vector<char> select(n);
    repeat (i, y) select[x + i] = 1;
    repeat (i, z) select[x + y + i] = 2;
    priority_queue<pair<ll, int> > que[3][3];
    auto push = [&](int i) {
        int p = select[i];
        repeat (q, 3) if (q != p) {
            que[p][q].emplace(a[i][q] - a[i][p], i);
        }
    };
    auto top = [&](int p, int q) {
        while (true) {
            int i = que[p][q].top().second;
            if (select[i] != p) {
                que[p][q].pop();
            } else {
                return i;
            }
        }
    };
    ll result = 0;
    repeat (i, n) {
        result += a[i][select[i]];
        push(i);
    }
    for (bool modified = true; modified; ) {
        modified = false;
        repeat (p, 3) repeat (q, 3) if (q != p) {
            while (true) {
                int i = top(p, q);
                int j = top(q, p);
                ll delta =
                    + a[i][q] - a[i][p]
                    + a[j][p] - a[j][q];
                if (delta > 0) {
                    result += delta;
                    select[i] = q;
                    select[j] = p;
                    que[p][q].pop();
                    que[q][p].pop();
                    push(i);
                    push(j);
                    modified = true;
                } else {
                    break;
                }
            }
            repeat (r, 3) if (r != p and r != q) {
                while (true) {
                    int i = top(p, q);
                    int j = top(q, r);
                    int k = top(r, p);
                    ll delta =
                        + a[i][q] - a[i][p]
                        + a[j][r] - a[j][q]
                        + a[k][p] - a[k][r];
                    if (delta > 0) {
                        result += delta;
                        select[i] = q;
                        select[j] = r;
                        select[k] = p;
                        que[p][q].pop();
                        que[q][r].pop();
                        que[r][p].pop();
                        push(i);
                        push(j);
                        push(k);
                        modified = true;
                    } else {
                        break;
                    }
                }
            }
        }
    }
    printf("%lld\n", result);
    return 0;
}
```
