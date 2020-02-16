---
layout: post
redirect_from:
  - /blog/2017/07/31/agc-017-c/
date: "2017-07-31T09:52:17+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc017/tasks/agc017_c" ]
---

# AtCoder Grand Contest 017: C - Snuke and Spells

## 反省

端から決めていく方向ばかり考えていた。
それが無理そうだというのは分かっていたが、ではどういうのなら解けるのかというのをちゃんと考えなかった。
区間のようなものは認識していたがきちんと区間として整理はしなかった。するべきだった。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<int> a(n);
    repeat (i, n) {
        scanf("%d", &a[i]); -- a[i];
    }
    // prepare
    vector<int> cnt(n);
    vector<int> covered(n);
    int sum = 0;
    auto push = [&](int x) {
        cnt[x] += 1;
        int l = x + 1 - cnt[x];
        if (l >= 0) {
            if (covered[l] == 0) sum += 1;
            covered[l] += 1;
        }
    };
    auto pop = [&](int x) {
        int l = x + 1 - cnt[x];
        if (l >= 0) {
            covered[l] -= 1;
            if (covered[l] == 0) sum -= 1;
        }
        cnt[x] -= 1;
    };
    // serve
    repeat (i, n) {
        push(a[i]);
    }
    repeat (i, m) {
        int x, y; scanf("%d%d", &x, &y); -- x; -- y;
        pop(a[x]);
        a[x] = y;
        push(a[x]);
        printf("%d\n", n - sum);
    }
    return 0;
}
```
