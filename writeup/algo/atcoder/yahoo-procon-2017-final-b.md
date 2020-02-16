---
layout: post
alias: "/blog/2017/03/26/yahoo-procon-2017-final-b/"
date: "2017-03-26T11:26:37+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon", "binary-search", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2017-final-open/tasks/yahoo_procon2017_final_b" ]
---

# 「みんなのプロコン」本選: B - チーム決め

## solution

二分探索。上限が固定されれば貪欲。$X = \max \\{ \max a_i, \max b_j \\}$として $O((N + M) \log X)$。

答え$\mathrm{ans}$が$\mathrm{ans} \le \mathrm{limit}$であるかの述語$\phi(\mathrm{limit})$を計算する。
$a, b$をsortし、$i$をひとつずつ増やしながら、$\|a_i - b_j\|$でまだ使われていない最小の$j$を(存在すれば)対応させていく。これは$O(N + M)$なので間に合う。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
const int inf = 1e9+7;
int main() {
    int n; scanf("%d", &n);
    int m; scanf("%d", &m);
    int k; scanf("%d", &k);
    vector<int> a(n); repeat (i,n) scanf("%d", &a[i]);
    vector<int> b(m); repeat (i,m) scanf("%d", &b[i]);
    whole(sort, a);
    whole(sort, b);
    auto pred = [&](int limit) {
        int cnt = 0;
        for (int i = 0, j = 0; i < n and j < m; ++ i) {
            while (j < m and b[j] < a[i] - limit) ++ j;
            if (j < m and abs(a[i] - b[j]) <= limit) {
                ++ j;
                ++ cnt;
            }
        }
        return k <= cnt;
    };
    int l = -1, r = inf;
    while (r - l > 1) {
        int m = (r + l) / 2;
        (pred(m) ? r : l) = m;
    }
    printf("%d\n", r);
    return 0;
}
```
