---
layout: post
redirect_from:
  - /blog/2017/09/02/arc-072-f/
date: "2017-09-02T08:06:58+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "deque" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc072/tasks/arc072_d" ]
---

# AtCoder Regular Contest 072: F - Dam

## solution

dequeでいい感じにする。$O(N)$。

水の流入の履歴をdequeで持ち、前から見ていく。
このとき流入する水の温度が時間に対して単調増加なら、履歴の先頭の水を流入しなかったことにすればよい。
新しい朝を迎えたときに単調増加の仮定が壊れる可能性がある。
これは前日の水と当日の水が同時に流れ込んで来たと見做すことで解消できる。
低い方の温度の水が流れ込んでくる前に水を捨てるのは損なのでこれでよい。
dequeの操作はならし$O(N)$回なので全体でも$O(N)$。

## 反省

単調増加の仮定を置くのに気付けなかった。
緩和は積極的にしていくべきぽい。

## implementation

``` c++
#include <cstdio>
#include <deque>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
using namespace std;

int main() {
    int n, l; scanf("%d%d", &n, &l);
    vector<int> t(n), v(n); repeat (i, n) scanf("%d%d", &t[i], &v[i]);
    deque<pair<int, double> > deq;
    deq.emplace_back(v[0], t[0]);
    double acc = t[0] *(double) v[0];
    printf("%.12lf\n", acc /(double) l);
    repeat_from (i, 1, n) {
        for (int nv = v[i]; nv > 0; ) {
            int dv = min(nv, deq.front().first);
            nv -= dv;
            deq.front().first -= dv;
            acc -= deq.front().second * dv;
            if (deq.front().first == 0) {
                deq.pop_front();
            }
        }
        int nv = v[i];
        double nt = t[i];
        while (not deq.empty() and deq.back().second > nt) {
            int pv; double pt; tie(pv, pt) = deq.back();
            deq.pop_back();
            nt = (nt * nv + pt * pv) / (nv + pv);
            nv += pv;
        }
        deq.emplace_back(nv, nt);
        acc += t[i] *(double) v[i];
        printf("%.12lf\n", acc /(double) l);
    }
    return 0;
}
```
