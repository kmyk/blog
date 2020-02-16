---
layout: post
redirect_from:
  - /blog/2017/07/02/icpc-2017-domestic-practice-c/
date: "2017-07-02T22:46:14+09:00"
tags: [ "competitive", "writeup", "aoj", "icpc-domestic" ]
---

# ACM-ICPC 2017 模擬国内予選: C. クイズ

## solution

各解答者について取りうる得点の最大値と最小値を求めればよい。$O(M + N^2)$。

得点の最大値は単に足し合わせればよい。
最小値は$0$というわけにはいかず、自分しか答えられない問題には必ず答えねばならない。
そのようにして最大最小を求め、全解答者対での得点の差の最大値$+1$が答え。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

int main() {
    while (true) {
        int n, m; scanf("%d%d", &n, &m);
        if (n == 0 and m == 0) break;
        vector<int> s_max(n);
        vector<int> s_min(n);
        repeat (i, m) {
            int s, k; scanf("%d%d", &s, &k);
            repeat (j, k) {
                int c; scanf("%d", &c); -- c;
                s_max[c] += s;
                if (k == 1) {
                    s_min[c] += s;
                }
            }
        }
        int result = 0;
        repeat (i, n) repeat (j, n) if (i != j) {
            setmax(result, s_max[j] - s_min[i] + 1);
        }
        printf("%d\n", result);
    }
    return 0;
}
```
