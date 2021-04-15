---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/123/
  - /blog/2016/09/21/yuki-123/
date: "2016-09-21T15:57:48+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/123" ]
---

# Yukicoder No.123 カードシャッフル

愚直。$N \le 50, M \le 10^5$なので$O(NM)$でやって間に合う。

pythonだと厳しい気がしてc++にしたが、その必要はなかったようだ。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    int n, m; cin >> n >> m;
    vector<int> b(n); whole(iota, b, 0);
    repeat (i,m) {
        int a; cin >> a; -- a;
        rotate(b.begin(), b.begin()+a, b.begin()+a+1);
    }
    cout << b.front()+1 << endl;
    return 0;
}
```
