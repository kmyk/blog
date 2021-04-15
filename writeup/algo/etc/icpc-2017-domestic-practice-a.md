---
layout: post
redirect_from:
  - /writeup/algo/etc/icpc-2017-domestic-practice-a/
  - /blog/2017/07/02/icpc-2017-domestic-practice-a/
date: "2017-07-02T22:35:52+09:00"
tags: [ "competitive", "writeup", "aoj", "icpc-domestic" ]
---

# ACM-ICPC 2017 模擬国内予選: A. JAG 模擬予選練習会

## solution

はい。$O(N)$。

注意点も特にない。

## implementation

``` c++
#include <cstdio>
#include <numeric>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f, x, ...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }

int main() {
    while (true) {
        int n, m; scanf("%d%d", &n, &m);
        if (n == 0 and m == 0) break;
        vector<int> v_max(m);
        repeat (i, n) {
            int d, v; scanf("%d%d", &d, &v);
            setmax(v_max[d - 1], v);
        }
        printf("%d\n", whole(accumulate, v_max, 0));
    }
    return 0;
}
```
