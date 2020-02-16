---
layout: post
alias: "/blog/2017/03/29/joisc2016-h/"
date: "2017-03-29T21:50:31+09:00"
tags: [ "competitive", "writeup", "atcoder", "joi", "square-root-decomposition" ]
---

# JOI春合宿2016: H - 回転寿司

-   <https://beta.atcoder.jp/contests/joisc2016/tasks/joisc2016_h>
-   <https://www.ioi-jp.org/camp/2016/2016-sp-tasks/index.html>

難しかったです。

-   区間の端点で分割して座圧っぽく$O(Q^2\log Q)$ $\to$ TLE
-   使い終わって区間を併合すれば $\to$ 焼け石に水
-   (ここで解説を見た)
-   bucketのindexのあたりのミス $\to$ WA
-   `int bucket_size = ceil(sqrt(query));` $\to$ TLE

## solution

平方分割。列とクエリの対称性を上手く使う。$O(Q \sqrt{N} (\log{N} + \log{Q}))$。

詳しくは公式解説

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <cmath>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using namespace std;
int main() {
    // input
    int n, query; scanf("%d%d", &n, &query);
    vector<int> x(n); repeat (i,n) scanf("%d", &x[i]);
    // square root decomposition
    int bucket_size = ceil(sqrt(n));
    int bucket_count = ceil(n /(double) bucket_size);
    vector<priority_queue<int> > bucket(bucket_count);
    vector<priority_queue<int> > bucket_query(bucket_count);
    auto flush = [&](int i) { // move bucket_query -> x
        if (bucket_query[i].empty()) return;
        int l = i * bucket_size;
        int r = min(n, (i+1) * bucket_size);
        repeat_from (j,l,r) {
            int value = - bucket_query[i].top();
            if (value < x[j]) {
                bucket_query[i].pop();
                bucket_query[i].push(- x[j]);
                x[j] = value;
            }
        }
        bucket_query[i] = priority_queue<int>();
    };
    auto reset = [&](int i) { // move x -> bucket
        int l = i * bucket_size;
        int r = min(n, (i+1) * bucket_size);
        bucket[i] = priority_queue<int>();
        repeat_from (j,l,r) {
            bucket[i].push(x[j]);
        }
    };
    // init
    repeat (i,bucket_count) {
        reset(i);
    }
    // run
    auto func = [&](int l, int r, int p) {
        int i = l / bucket_size;
        if (l % bucket_size != 0) {
            flush(i);
            int limit = min(r, (i+1) * bucket_size);
            for (; l < limit; ++ l) if (p < x[l]) swap(p, x[l]);
            reset(i);
            ++ i;
        }
        for (; l + bucket_size - 1 < r; l += bucket_size, ++ i) {
            int value = bucket[i].top();
            if (p < value) {
                bucket_query[i].push(- p);
                bucket[i].pop();
                bucket[i].push(p);
                p = value;
            }
        }
        if (l != r) {
            flush(i);
            for (; l < r; ++ l) if (p < x[l]) swap(p, x[l]);
            reset(i);
        }
        return p;
    };
    while (query --) {
        int l, r, p; scanf("%d%d%d", &l, &r, &p); -- l;
        if (l < r) {
            p = func(l, r, p);
        } else {
            p = func(l, n, p);
            p = func(0, r, p);
        }
        // output
        printf("%d\n", p);
    }
    return 0;
}
```
