---
layout: post
redirect_from:
  - /writeup/algo/atcoder/dwacon2018-final-a/
  - /blog/2018/02/14/dwacon2018-final-a/
date: "2018-02-14T02:32:24+09:00"
tags: [ "competitive", "writeup", "atcoder", "dwacon" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2018-final-open/tasks/dwacon2018_final_a" ]
---

# 第4回 ドワンゴからの挑戦状 本選: A - アナログ時計

面倒やるだけなので嫌い。

## solution

$1$秒ずつ進める。おおよそ$60$秒に$1$回 分針と秒針が重なるので$60C\_1$秒くらい見れば十分。計算量としては$O(\min \{ C\_1, C\_2 \})$。

## implementation

``` c++
#include <bits/stdc++.h>
using namespace std;

int main() {
    // input
    int h, m, s; cin >> h >> m >> s;
    int c1, c2; cin >> c1 >> c2;

    // solve
    h %= 12;
    assert (not (m == 0 and s == 0));
    int t1 = -1, t2 = -1;
    if (c1 == 0 and c2 == 0) {
        t1 = t2 = 0;
    }
    for (int t = 1; c1 >= 0 and c2 >= 0; ++ t) {
        double ah = (3600 * h + 60 * m + s) / 43200.0;
        double am = (60 * m + s) / 3600.0;
        double as = s / 60.0;
        bool d1 =             (m == 59 and s == 59) or (as < am and am + 1 /  3600.0 < as + 1 /   60.0);
        bool d2 = (h == 11 and m == 59 and s == 59) or (am < ah and ah + 1 / 43200.0 < am + 1 / 3600.0);
        s += 1;
        if (s == 60) {
            s = 0;
            m += 1;
            if (m == 60) {
                m = 0;
                h += 1;
                if (h == 12) {
                    h = 0;
                }
            }
        }
        c1 -= d1;
        c2 -= d2;
        if (c1 == 0 and c2 == 0 and not (m == 0 and s == 0)) {
            if (t1 == -1) t1 = t;
            t2 = t;
        }
    }

    // output
    if (t1 == -1) {
        cout << -1 << endl;
    } else {
        cout << t1 << ' ' << t2 << endl;
    }
    return 0;
}
```
