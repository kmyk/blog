---
layout: post
alias: "/blog/2018/01/04/codefestival-2016-grand-final-a/"
title: "CODE FESTIVAL 2016 Grand Final: A - 1D Matching"
date: "2018-01-04T16:09:17+09:00"
tags: [ "competitive", "writeup", "atcodr", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-exhibition-final/tasks/cf16_exhibition_final_a" ]
---

まあはいだけどなんだか解説が書きにくかった。

## solution

まだ使ってないものの数を数えながら座標の小さい方から順に見ていく。$O(N \log N)$。

位置$x, x'$のパソコンをそれぞれ位置$y, y'$の電源に繋ぐとき、$\max \\{ x, x' \\} \le \min \\{ y, y' \\}$なら$2$通りの繋ぎ方ができ、そうでなければ$1$通りのみである。
位置$x, x', x''$のパソコンをそれぞれ位置$y, y', y'''$の電源に繋ぐとき、$\max \\{ x, x', x'' \\} \le \min \\{ y, y', y'' \\}$なら$3!$通りの繋ぎ方ができる。
そうでない場合はそうでない。繋ぎ方を矢印で書いたとき、違う向きの矢印が重なってはいけない。
このように考えると、ある種の連結成分ごとに独立に計算できる。
ある連結成分を計算するとき、向きは左端や右端を見れば定まる。
まだ使ってないものの種類と数を覚えておきながら端から舐め、新しく見たものが組み合わせて使える場合はどれかひとつ好きに選んで使う。
これは覚えていた数$k$を全体の結果に乗算する。


## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;

constexpr int mod = 1e9+7;
int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    vector<int> b(n); repeat (i, n) scanf("%d", &b[i]);
    // solve
    vector<pair<int, bool> > events;
    repeat (i, n) {
        events.emplace_back(a[i], false);
        events.emplace_back(b[i], true);
    }
    sort(whole(events));
    ll result = 1;
    int cnt = 0;
    for (auto event : events) {
        int delta = (event.second ? 1 : -1);
        if (cnt != 0 and (cnt > 0) != event.second) {
            result = (result * std::abs(cnt)) % mod;
        }
        cnt += delta;
    }
    // output
    printf("%lld\n", result);
    return 0;
}
```
