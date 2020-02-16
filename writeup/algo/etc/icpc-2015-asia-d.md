---
layout: post
alias: "/blog/2015/11/30/icpc-2015-asia-d/"
date: 2015-11-30T01:24:33+09:00
tags: [ "competitive", "writeup", "icpc", "aoj", "greedy" ]
---

# ACM ICPC 2015 アジア地区予選 D : Wall Clocks

本番では私は読んでない。
これを読んだチームメンバーからさらっと話を聞いたのみである。
チーム全体としても、ほぼ手を付けていない。
やる時間があれば解けていたのではと思う。

<!-- more -->

## [D : Wall Clocks](http://judge.u-aizu.ac.jp/onlinejudge/cdescription.jsp?cid=ICPCOOC2015&pid=D) {#d}

### 問題

$H\times W$の部屋がある。部屋には人が複数人いて、格子点上で、x軸あるいはy軸に並行な方向を向いており、ちょうど90度の視野を持つ。
部屋の壁に時計を複数個掛けて、部屋の全ての人から時計が見えるようにしたい。
最小でいくつの時計が必要か。

### 解法

1次元に落としてDP。$O(n^2)$。

時計は壁にしか設置せず、ある人の視野の範囲は壁の上で連続である。
なので、壁をループした1次元に落とし、視野はその上の区間$[l,r)$に移せる。

最初のひとつめの時計を用いる場所を定め、その時計を含む区間を取り除くと、残りの部分はループのない1次元と見ることができるようになる。するとこれは単純な$O(n)$の貪欲で解ける。
最初のひとつめの時計を用いる場所は、ある人の視野の右端か左端のみであるから、高々$2n$個のみ試せばよい。ひとつめの時計の場所のすべての可能性に対し貪欲法で結果を求め、その最小を答えればよい。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int dtoi(char c) { // direction to index
    return c == 'N' ? 0 :
           c == 'S' ? 1 :
           c == 'E' ? 2 :
           c == 'W' ? 3 : -1;
}
int itoyl[] = { 1, -1, 1, -1 }; // direction index to difference of y of left edge
int itoxl[] = { -1, 1, 1, -1 };
int itoyr[] = { 1, -1, -1, 1 };
int itoxr[] = { 1, -1, 1, -1 };
int proj_ix(int y, int x, int h, int w) {
    if (x == 0) return y;
    if (y == h) return h + x;
    if (x == w) return h + w + (h-y);
    if (y == 0) return h + w + h + (w-x);
    return -1;
}
int proj(int y, int x, int dy, int dx, int h, int w) {
    while (proj_ix(y, x, h, w) == -1) {
        y += dy;
        x += dx;
    }
    return proj_ix(y, x, h, w);
}
bool proj_in(int i, int l, int r, int len) {
    if (l <= i and i <= r) return true;
    if (r < l and l <= i) return true;
    if (r < l and i <= r) return true;
    return false;
}
int greedy(int initial, int n, int len, vector<int> const & l, vector<int> const & r) {
    vector<pair<int,int> > intervals;
    repeat (i,n) {
        if (not proj_in(initial, l[i], r[i], len)) {
            intervals.push_back(make_pair((l[i] - initial + len) % len,
                                          (r[i] - initial + len) % len));
        }
    }
    sort(intervals.begin(), intervals.end());
    int result = 1 + not intervals.empty();
    int q = 1000000007;
    for (auto p : intervals) {
        if (q < p.first) {
            result += 1;
            q = p.second;
        } else {
            q = min(q, p.second);
        }
    }
    return result;
}
int main() {
    int n, w, h; cin >> n >> w >> h;
    vector<int> l(n), r(n); // [l, r]
    repeat (i,n) {
        int x, y; char c; cin >> x >> y >> c;
        int d = dtoi(c);
        l[i] = proj(y, x, itoyl[d], itoxl[d], h, w);
        r[i] = proj(y, x, itoyr[d], itoxr[d], h, w);
    }
    int result = 1000000007;
    repeat (i,n) {
        result = min(result, greedy(l[i],n,2*(w+h),l,r));
        result = min(result, greedy(r[i],n,2*(w+h),l,r));
    }
    cout << result << endl;
    return 0;
}
```
