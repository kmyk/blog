---
layout: post
redirect_from:
  - /writeup/algo/etc/icpc-2016-domestic-a/
  - /blog/2016/06/27/icpc-2016-domestic-a/
date: 2016-06-27T13:01:44+09:00
tags: [ "competitive", "writeup", "icpc" ]
---

# ACM-ICPC 2016 国内予選 A: 被験者の選定

-   <http://icpcsec.storage.googleapis.com/icpc2016-domestic/problems/all_ja.html#section_A>
-   <http://icpc.iisf.or.jp/past-icpc/domestic2016/judgedata/A/>

## solution

-   各$2$点対に関して見て間に合う。$O(N^2)$。
-   事前にsortすれば隣接項間を$1$回なめるだけでよい。$O(N \log N)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const int inf = 1e9+7;
int main() {
    while (true) {
        int n; cin >> n;
        if (n == 0) break;
        vector<int> a(n); repeat (i,n) cin >> a[i];
        int d_min = inf;
        repeat (i,n) repeat (j,i) setmin(d_min, abs(a[j] - a[i]));
        cout << d_min << endl;
    }
    return 0;
}
```
