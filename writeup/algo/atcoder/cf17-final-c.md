---
layout: post
alias: "/blog/2017/11/26/cf17-final-c/"
date: "2017-11-26T10:02:23+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "exhaustive-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-final-open/tasks/cf17_final_c" ]
---

# CODE FESTIVAL 2017 Final: C - Time Gap

## solution

左右への振り分けを全列挙。$D\_i$の上限を$L = 12$として$O(N + L2^L)$。

$D\_i = 0, 12$のとき$D\_i \equiv 24 - D\_i$なので元の時刻は一意に定まり、それ以外が問題。
ふたつの都市の標準時が同じ時刻であると$s = 0$となるので、$D\_i = k$となる$i$が$2$つ以上なら選択の余地はない。
ひとつのときだけが問題になるが、それぞれ左右のどちらに振るかを$2^{11}$通り全て試して間に合う。

## implementation

``` c++
#include <algorithm>
#include <array>
#include <climits>
#include <cmath>
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> d(n); repeat (i, n) scanf("%d", &d[i]);
    // solve
    array<int, 13> cnt = {};
    cnt[0] += 1;
    for (int d_i : d) cnt[d_i] += 1;
    int max_s = -1;
    repeat (pred, (1 << 11)) {
        array<bool, 24> used = {};
        int s = INT_MAX;
        repeat (i, 13) if (cnt[i]) {
            if (i == 0 or i == 12) {
                used[i] = true;
                if (cnt[i] >= 2) {
                    s = 0;
                }
            } else {
                if (cnt[i] == 1) {
                    used[pred & (1 << (i - 1)) ? i : 24 - i] = true;
                } else if (cnt[i] == 2) {
                    used[i] = used[24 - i] = true;
                } else {
                    s = 0;
                }
            }
        }
        repeat (i, 24) if (used[i]) {
            repeat (j, i) if (used[j]) {
                setmin(s, min(abs(i - j), 24 - abs(i - j)));
            }
        }
        setmax(max_s, s);
    }
    // output
    printf("%d\n", max_s);
    return 0;
}
```
