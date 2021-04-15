---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_062_e/
  - /writeup/algo/atcoder/arc-062-e/
  - /blog/2016/10/15/arc-062-e/
date: "2016-10-15T23:54:58+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "combination" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc062/tasks/arc062_c" ]
---

# AtCoder Regular Contest 062 E - AtCoDeerくんと立方体づくり / Building Cubes with AtCoDeer

環境が普段と違うこともあり、分からなかったら撤退のつもりで$3$問目のこれからopenした。
そして解けた。
結果はかなりよくて、パフォーマンス値で言えばぎりぎり赤でないぐらいの値だった。

## solution

向かい合う$2$面を決定すれば頂点の色は全て決まる。$O(N^2 \log N)$。

頂点の色が決まっているとして、側面の埋め方が何通りあるか考えればよい。
ある側面に関して頂点の色の要求が$(c_0, c_1, c_2, c_3)$だったとして、そのようなタイルが何枚あるかは事前に数えておけるので、$O(\log N)$で引いてきて(permutationの計算のようにして)掛け合わせればよい。
`map`等を使うにあたっては回転に関して最小を取るなどして正規化をする必要がある。
また$c_0 = c_2 \land c_1 = c_3$等の場合、同じ側面に同じタイルであっても複数の貼り方が存在するので、これを計算しておいて掛けてやる必要がある。

重複除去は考えず全部だして、最後に正面$6$通り回転$4$通りの$24$で割れば答えになる。
ただし速度やoverflowの懸念からできる範囲で除去すべきではある。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <array>
#include <map>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
typedef uint16_t color_t;
array<color_t,4> rotate(array<color_t,4> c, int r) {
    rotate(c.begin(), c.begin() + r, c.end());
    return c;
}
void normalize(array<color_t,4> & c) {
    array<color_t,4> d = c;
    repeat (r,4) setmin(c, rotate(d, r));
}
int multiplicity(array<color_t,4> const & c) {
    int n = 0;
    repeat (r,4) if (c == rotate(c, r)) n += 1;
    return n;
}
int main() {
    int n; cin >> n;
    vector<array<color_t,4> > c(n);
    repeat (i,n) repeat (j,4) cin >> c[i][j];
    repeat (i,n) normalize(c[i]);
    map<array<color_t,4>,int> cnt; repeat (i,n) cnt[c[i]] += 1;
    map<array<color_t,4>,int> mul; for (auto it : cnt) mul[it.first] = multiplicity(it.first);
    ll ans = 0;
    repeat (bi,n) repeat (ai,bi) { // div 2
        cnt[c[ai]] -= 1;
        cnt[c[bi]] -= 1;
        repeat (br,4) { // div 4
            //    b0 -- b3
            //   /     / |
            // a0 -- a1  |
            //  | _1  | b2
            //  |     | /
            // a3 -- a2
            array<color_t,4> const & a = c[ai];
            array<color_t,4> b = rotate(c[bi], br);
            array<array<color_t,4>,4> ds;
            ds[0] = { b[0], b[3], a[1], a[0] };
            ds[1] = { b[3], b[2], a[2], a[1] };
            ds[2] = { b[2], b[1], a[3], a[2] };
            ds[3] = { b[1], b[0], a[0], a[3] };
            ll acc = 1;
            map<array<color_t,4>,int> used;
            for (auto & d : ds) {
                normalize(d);
                if (not cnt.count(d)) { acc = 0; break; }
                used[d] += 1;
                acc *= mul[d] * (cnt[d] - used[d] + 1);
            }
            ans += acc;
        }
        cnt[c[ai]] += 1;
        cnt[c[bi]] += 1;
    }
    assert (ans % 3 == 0);
    ans /= 3; // div 3
    cout << ans << endl;
    return 0;
}
```
