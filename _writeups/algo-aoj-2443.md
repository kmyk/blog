---
layout: post
redirect_from:
  - /writeup/algo/aoj/2443/
  - /blog/2016/07/04/aoj-2443/
date: "2016-07-04T14:55:08+09:00"
tags: [ "competitive", "writeup", "aoj", "meet-in-the-middle", "permutation" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2443" ]
---

# AOJ 2443. ReverseSort

解けず。
不一致区間の長さが真に縮むように貪欲っぽく取ればよいかと思ったがWAった。

## solution

半分全列挙。

全ての${}\_NC_2$個の全ての反転方法に関して深さ$\frac{N-1}{2} = 4$まで再帰的に試す。
深さ$5$のやつは触らない。半分全列挙したふたつに一致がなければ$\mathrm{ans} = N-1$。

## implementation

階乗進数へのencode/decodeのあたりは要らなかった。

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <numeric>
#include <map>
#include <queue>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
void bfs(vector<int> xs, map<vector<int>,int> & memo) {
    int n = xs.size();
    queue<vector<int> > que;
    que.emplace(xs);
    while (not que.empty()) {
        vector<int> xs = que.front(); que.pop();
        int depth = memo[xs];
        repeat (r,n+1) repeat (l,r-1) {
            reverse(xs.begin() + l, xs.begin() + r);
            if (not memo.count(xs)) {
                memo[xs] = depth + 1;
                if (depth+1 < (n-1)/2) {
                    que.emplace(xs);
                }
            }
            reverse(xs.begin() + l, xs.begin() + r);
        }
    }
};
int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n);
    repeat (i,n) {
        scanf("%d", &a[i]);
        -- a[i];
    }
    // compute
    map<vector<int>,int> memo_l, memo_r;
    vector<int> b(n); iota(b.begin(), b.end(), 0);
    bfs(b, memo_l);
    bfs(a, memo_r);
    int ans = n-1;
    do {
        if (memo_l.count(b) and memo_r.count(b)) {
            setmin(ans, memo_l[b] + memo_r[b]);
        }
    } while (next_permutation(b.begin(), b.end()));
    // output
    printf("%d\n", ans);
    return 0;
}
```
