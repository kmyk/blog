---
layout: post
alias: "/blog/2015/11/20/code-festival-2015-morning-f/"
title: "CODE FESTIVAL 2015 朝プロ F - 立方体とペンキ"
date: 2015-11-20T01:54:41+09:00
tags: [ "competitive", "writeup", "codefestival", "atcoder" ]
---

本番で通せず。$k \le 10^{14}$だしpythonだなあとか言って`queue.PriorityQueue`で頑張ろうとしてた。どう見ても頭回ってない。前日深夜のgolfが響いたのだろうか。

<!-- more -->

## [F - 立方体とペンキ](https://beta.atcoder.jp/contests/code-festival-2015-morning-hard/tasks/cf_2015_morning_hard_b) {#f}

### 問題

$1 \times N$のマス目の上に$1 \times 1 \times 1$の立方体がたくさん積まれている。
各マスについて、いくつの立方体が積まれているか与えられる。
ここから$K$個の立方体を取り除き、立方体の表面積を最小化し、その値を答えよ。
どのマスにもひとつ以上の立方体は積まれており、この条件は保つものとする。

### 解法

同じ高さの列はひとつにまとめ、その幅に関するpriority queueで頑張る。
実装するだけ。

`struct block_t { ll height, width; }`, `struct top_t { list<block_t>::iterator it; }`と構造体を作って、`list<block_t>`と`priority_queue<top_t>`を持って、`list<block_t>`を縮めていくと楽かなと思う。

### 実装

ちょっと眠たい中、一発で実装できたので嬉しい。

``` c++
#include <iostream>
#include <vector>
#include <list>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
struct block_t {
    ll height, width;
};
struct top_t {
    list<block_t>::iterator it;
};
bool operator < (top_t const & a, top_t const & b) {
    return a.it->width > b.it->width; // reversed, for priority_queue
}
int main() {
    int n; ll k; cin >> n >> k;
    vector<ll> a(n); repeat (i,n) cin >> a[i];
    ll result = 0;
    list<block_t> b; // run length compressed
    // make initial b and result
    b.push_back((block_t){ 0, 0 });
    repeat (i,n) {
        ll h = a[i];
        result += (2 * h) + 1 + abs((i == 0 ? 0 : a[i-1]) - h);
        if (b.back().height == h) {
            b.back().width += 1;
        } else {
            b.push_back((block_t){ h, 1 });
        }
    }
    result += a.back();
    b.push_back((block_t){ 0, 0 });
    // gather tops
    priority_queue<top_t> q;
    for (auto it = b.begin(); it != b.end(); ++ it) {
        if (it == b.begin()) continue;
        auto l = it; -- l;
        auto r = it; ++ r;
        if (r != b.end()) {
            if (l->height < it->height and r->height < it->height) {
                q.push((top_t){ it });
            }
        }
    }
    // remove cubes
    while (not q.empty()) {
        auto it = q.top().it; q.pop();
        if (it->height <= 1) break;
        auto l = it; -- l;
        auto r = it; ++ r;
        ll d = it->height - max(max(l->height, r->height), 1ll); // how many rows are deleted
        if (d * it->width <= k) { // k is enough
            k -= d * it->width;
            result -= (d * it->width * 2) + (d * 2);
            it->height -= d;
            // merge
            for (auto that : { l, r }) {
                if (it->height == that->height) {
                    it->width += that->width;
                    b.erase(that);
                }
            }
            // next
            l = it; -- l;
            r = it; ++ r;
            if (l->height < it->height and r->height < it->height) {
                q.push((top_t){ it });
            }
        } else { // k is not enough
            d = k / it->width;
            k %= it->width;
            result -= (d * it->width * 2) + (d * 2);
            result -= k * 2;
            break;
        }
    }
    cout << result << endl;
    return 0;
}
```
