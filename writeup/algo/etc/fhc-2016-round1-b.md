---
layout: post
alias: "/blog/2016/01/18/fhc-2016-round1-b/"
title: "Facebook Hacker Cup 2016 Round 1 Laundro, Matt"
date: 2016-01-18T01:17:34+09:00
tags: [ "competitive", "writeup", "facebook-hacker-cup", "greedy", "simulation" ]
---

## [Laundro, Matt](https://www.facebook.com/hackercup/problem/1611251319125133/)

### 問題

洗濯物が$L$個、洗濯機が$N$台、乾燥機が$M$台ある。
洗濯機はそれぞれ$W_i$分で1個洗濯でき、全ての乾燥機は$D$分で1個乾燥させられる。
洗濯物を全て洗濯し乾燥させるには最小で何分かかるか。

### 問題

simulation + 貪欲。

とりあえず全部の洗濯機を動かす。
早く終わった洗濯機に洗濯機を入れていたことにする。
乾燥は洗濯ができた順にする。

二分探索は不要。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <queue>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
struct event_t { ll t; int i; };
bool operator < (event_t a, event_t b) { return a.t > b.t; } // reversed, preorder
ll solve() {
    ll l, n, m, d; cin >> l >> n >> m >> d;
    vector<ll> w(n); repeat (i,n) cin >> w[i];
    int unwashed = l;
    int undried = 0;
    int done = 0;
    int free_drier = m;
    priority_queue<event_t> q;
    repeat (i,n) q.push((event_t){ w[i], i });
    while (not q.empty()) {
        event_t e = q.top(); q.pop();
        if (e.i >= 0) { // washing done
            if (unwashed > 0) {
                -- unwashed;
                if (free_drier > 0) {
                    -- free_drier;
                    q.push((event_t){ e.t + d, -1 });
                } else {
                    ++ undried;
                }
            }
            if (unwashed > 0) {
                q.push((event_t){ e.t + w[e.i], e.i });
            }
        } else { // drying done
            ++ done;
            if (done == l) return e.t;
            if (undried > 0) {
                -- undried;
                q.push((event_t){ e.t + d, -1 });
            } else {
                ++ free_drier;
            }
        }
    }
    assert (false);
}
int main() {
    int testcases; cin >> testcases;
    repeat (testcase, testcases) {
        cout << "Case #" << testcase+1 << ": " << solve() << endl;
    }
    return 0;
}
```
