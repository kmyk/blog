---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-013-c/
  - /blog/2017/10/03/agc-013-c/
date: "2017-10-03T04:55:46+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc013/tasks/agc013_c" ]
---

# AtCoder Grand Contest 013: C - Ants on a Circle

後輩に「おすすめの問題ある？」と聞いたら出てきたやつ。
$700$点にしてはつらかった。

## solution

$O(N \log N)$。

蟻本の蟻の問題と同じで、完全弾性衝突のため番号を無視して動きだけ見れば衝突はない。
相対的な位置関係も変化しないので、$0$番目の蟻の$T$秒後の位置が分かれば十分である。
移動方向の変化を追うのは難しいので、蟻が衝突したときその番号を交換すると考える。
最初に$0$番目だった蟻が最後にどの番号を持つかを求めても同様に答えは復元できる。
相対的な位置関係は変化しなかったので、番号の交換は右向きに進む蟻の番号を$1$増やし左向きに進む蟻の番号を$1$減らすとしても同じ。
最初に$0$番目だった蟻が他の蟻と衝突する回数は合計$O(N)$かければ求まり、その回数が最終的な番号である。
これで答えが求まる。

## implementation

``` c++
#include <algorithm>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using ll = long long;
using namespace std;

vector<int> solve(int n, ll l, ll t, vector<int> const & x, vector<int> const & w) {
    ll cnt = 0;
    repeat (i, n) if (w[0] != w[i]) {
        int dx = x[i] - x[0];
        dx = (w[0] == 1 ? dx : l - dx);
        cnt += (2 * t - dx + l) / l;
    }
    cnt %= n;
    vector<int> y(n);
    int z = 0;
    repeat (i, n) {
        y[i] = ((x[i] + (w[i] == 1 ? +1ll : -1ll) * t) % l + l) % l;
        if (y[i] == y[0]) z = i;
    }
    int y_0 = y[0];
    sort(whole(y));
    int ofs = find(whole(y), y_0) - y.begin();
    if (z and w[0] < w[z]) ++ ofs;
    int shift = (w[0] == 1 ? - cnt + ofs + n : cnt + ofs) % n;
    rotate(y.begin(), y.begin() + shift, y.end());
    return y;
}

int main() {
    int n, l, t; scanf("%d%d%d", &n, &l, &t);
    vector<int> x(n), w(n); repeat (i, n) scanf("%d%d", &x[i], &w[i]);
    vector<int> y = solve(n, l, t, x, w);
    for (int y_i : y) {
        printf("%d\n", y_i);
    }
    return 0;
}
```
