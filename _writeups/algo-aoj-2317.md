---
layout: post
redirect_from:
  - /writeup/algo/aoj/2317/
  - /blog/2016/06/29/aoj-2317/
date: 2016-06-29T00:11:42+09:00
tags: [ "competitive", "writeup", "aoj", "coordinates-compression" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2317" ]
---

# AOJ 2317: Class Representative Witch

ストーリーが楽しげなのはいいが、そのせいか問題文が分かりにくい。ほむほむ。

## problem

$1$次元上に、向きの付いた区間$\vec{[l,r)}$と座標$p_i$が複数与えられる。
各区間について、その区間を与えられた座標$p_i$で分割し、区間の列$[l,p_j), [p_j,p\_{j+1}), [p_j,p\_{j+2}), \dots, [p\_{j+k},r)$を作る。
これらの列の偶数番目の区間の全てについて、その長さを足し合わせたものを答えよ。
$r \lt l$であるような区間$\vec{[l,r)}$を分解した結果に関して、その$0$番目の区間とは$[p_j,r)$の形をしていることに注意せよ。

## solution

なんらかの座標圧縮をする。$O(N+M)$。

## implementation

`priority_queue`にeventとして詰めて空間を舐めた。
ある点を含む区間で、有効な区間の数$c\_\mathrm{on}$と無効な区間の数$c\_\mathrm{off}$を持ち、$p_j$による反転クエリごとにこれら$c\_\mathrm{on},c\_\mathrm{off}$をswapした。
負の向きの区間に関しては、$-1$を掛けて向きを反転させることで処理した。

ところで`union`はあまり使いたくないし早く`std::variant`が来てほしい。

``` c++
#include <iostream>
#include <vector>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;

const int open_tag = 1;
const int close_tag = 2;
const int toggle_tag = 3;
union event_t {
    struct { int tag; int t; } common;
    struct { int tag; int l, i; } open; // [l, r)
    struct { int tag; int r, i; } close; // [l, r)
    struct { int tag; int p; } toggle;
};
bool operator < (event_t a, event_t b) { return a.common.t > b.common.t; } // weak struct ordering
int main() {
    // init
    int n, m; cin >> n >> m;
    priority_queue<event_t> que;
    repeat (i,n) {
        int s, t; cin >> s >> t;
        event_t el = { open_tag };
        event_t er = { close_tag };
        if (s < t) {
            el.open .l = s;
            er.close.r = t;
        } else {
            el.open .l = - s;
            er.close.r = - t;
        }
        el.open .i = i;
        er.close.i = i;
        que.push(el);
        que.push(er);
    }
    repeat (i,m) {
        int p; cin >> p;
        event_t e = { toggle_tag };
        e.toggle.p = p;
        que.push(e);
        e.toggle.p = - p;
        que.push(e);
    }
    // run
    ll ans = 0;
    int prv = 0;
    int on = 0;
    int off = 0;
    vector<int> ix(n, -1);
    vector<int> acc { 0 };
    while (not que.empty()) {
        event_t e = que.top(); que.pop();
        ans += on *(ll) (e.common.t - prv);
        prv = e.common.t;
        if (e.common.tag == open_tag) {
            on += 1;
            ix[e.open.i] = acc.size() - 1;
            acc.push_back(acc.back());
        } else if (e.common.tag == close_tag) {
            ((acc.back() - acc[ix[e.close.i]]) % 2 == 0 ? on : off) -= 1;
        } else if (e.common.tag == toggle_tag) {
            swap(on, off);
            acc.back() += 1;
        }
    }
    // output
    cout << ans << endl;
    return 0;
}
```
