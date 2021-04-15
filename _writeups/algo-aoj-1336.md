---
layout: post
redirect_from:
  - /writeup/algo/aoj/1336/
  - /blog/2017/12/04/aoj-1336/
date: "2017-12-04T10:53:13+09:00"
tags: [ "competitive", "writeup", "aoj", "icpc", "icpc-asia", "ant" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1336" ]
---

# AOJ 1336. The Last Ant

## problem

長さ$l$の道の上に$n$匹の向き付けられた蟻がいる。時刻$0$に同時に単位速度で歩きだす。
道には狭い部分と広い部分が交互にあり、狭い部分で衝突すると反転、広い部分で衝突するとすり抜ける。
最後に蟻が落ちる時刻とそのような蟻の番号を答えよ。

## solution

蟻ゲー。$O(n \log n)$。

偶奇が同じもの同士は完全弾性衝突し、異なるものは素通りする。
落下が発生する時刻と向きは列挙できる。
つまり最後に落下する時刻と向きがすぐに分かる (同時に両側から落ちる場合は上手くやる)。番号だけが問題。
最後に落下する蟻の位置の偶奇も分かるので偶奇が一致するものだけ集め一列に並べ、落ちる向きに合わせて左右から削っていけば最後に残る蟻が答え。
indexの操作が多くて混乱も多いが上手くやる。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <numeric>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;

int main() {
    while (true) {
        // input
        int n, l; scanf("%d%d", &n, &l);
        if (n == 0 and l == 0) break;
        vector<char> d(n);
        vector<int> p(n);
        repeat (i, n) {
            scanf(" %c%d", &d[i], &p[i]);
        }
        // solve
        vector<int> t(n);
        repeat (i, n) {
            t[i] = (d[i] == 'L' ? p[i] : l - p[i]);
        }
        auto cmp = [&](int i, int j) {
            return make_pair(t[i], d[i] == 'L') < make_pair(t[j], d[j] == 'L');
        };
        vector<int> xs(n);
        iota(whole(xs), 0);
        bool last_parity = p[*max_element(whole(xs), cmp)] % 2;
        xs.erase(remove_if(whole(xs), [&](int i) {
            return p[i] % 2 != last_parity;
        }), xs.end());
        sort(whole(xs), cmp);
        int last_j = 0;
        repeat (i, xs.size() - 1) {
            if (d[xs[i]] == 'L') {
                ++ last_j;
            }
        }
        sort(whole(xs));
        last_j = xs[last_j];
        // output
        int last_t = *max_element(whole(t));
        printf("%d %d\n", last_t, last_j + 1);
    }
    return 0;
}
```
