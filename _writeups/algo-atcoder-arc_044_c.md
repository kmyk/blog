---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_044_c/
  - /writeup/algo/atcoder/arc-044-c/
  - /blog/2015/11/03/arc-044-c/
date: 2015-11-03T18:18:43+09:00
tags: [ "competitive", "arc", "atcoder", "writeup" ]
---

# AtCoder Regular Contest 044 C - ビーム

分からないのでヒントを見てしまった。自力で解く/解けるべきだった。

<!-- more -->

## [C - ビーム](https://beta.atcoder.jp/contests/arc044/tasks/arc044_c) {#c}

### 問題

プレイヤーは$H\times W$の盤上にいる。
プレイヤーは隣接する4マスに好きなだけ移動できる。
座標軸と並行にビームが飛んでくるので、全て回避したい。
最小の移動回数を求めよ。

### 解法

クエリは縦と横で独立なので分割しそれぞれ計算。 $O(Q)$。

移動するのは現在位置にビームが来たときだけでよい。
また、来たビームに垂直な方向のいずれかに最小の距離だけでよい。
ただし、複数のビームが同じ時間に来て、太いものになっている場合があることに注意。

ここから縦のビームと横のビームが独立であることが分かる。
すると$H \times 1$と$1 \times W$の盤面に分けて考えることができ、ひとつのクエリは$O(1)$で処理できる。

### 実装

`sort`を忘れててWA。始めは気付いていたので、`vector`じゃなくて`set`にすべきかなあとか頭に浮かんでいたが、いつの間にか消えていた。

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <algorithm>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
constexpr int inf = 1000000007;
int min_steps(int l, map<int,vector<int> > & qs) {
    vector<int> xs(l);
    for (auto & q : qs) {
        vector<int> & beams = q.second;
        sort(beams.begin(), beams.end());
        for (int x : beams) if (x+1 < l) xs[x+1] = min(xs[x+1], xs[x] + 1);
        reverse(beams.begin(), beams.end());
        for (int x : beams) if (0 <= x-1) xs[x-1] = min(xs[x-1], xs[x] + 1);
        for (int x : beams) xs[x] = inf;
    }
    return *min_element(xs.begin(), xs.end());
}
int main() {
    int w, h, q; cin >> w >> h >> q;
    map<int,vector<int> > hq, vq; // horizontal/vertical query: time -> position
    repeat (i,q) {
        int t, d, x; cin >> t >> d >> x;
        -- x;
        (d ? hq : vq)[t].push_back(x);
    }
    int y = min_steps(h, hq);
    int x = min_steps(w, vq);
    cout << (y == inf or x == inf ? -1 : x + y) << endl;
    return 0;
}
```

### 参考

-   [AtCoder ARC #044 : C - ビーム - kmjp&#39;s blog](http://kmjp.hatenablog.jp/entry/2015/09/12/1100)
