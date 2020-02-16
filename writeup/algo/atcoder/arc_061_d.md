---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-061-d/
  - /blog/2016/09/14/arc-061-d/
date: "2016-09-14T13:08:54+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc061/tasks/arc061_b" ]
---

# AtCoder Regular Contest 061 D - すぬけ君の塗り絵 / Snuke's Coloring

## solution

黒マスが存在するのは指定された$N$マスだけなので、$(H-2)(W-2)$個の全部でなくて、黒マスの周囲の高々$9N$マスのみ調べればよい。
$O(N)$。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <array>
#include <set>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    // input
    int h, w, n; cin >> h >> w >> n;
    vector<int> a(n), b(n); repeat (i,n) { cin >> a[i] >> b[i]; -- a[i]; -- b[i]; }
    // compute
    set<pair<int,int> > exists;
    repeat (i,n) exists.emplace(a[i], b[i]);
    set<pair<int,int> > used;
    auto is_on_field = [&](int y, int x) { return 0 <= y and y <= h-3 and 0 <= x and x <= w-3; };
    array<ll,10> ans = {};
    ans[0] = (h-2) *(ll) (w-2);
    repeat (i,n) {
        for (int dy : { -2, -1, 0 }) {
            for (int dx : { -2, -1, 0 }) {
                int y = a[i] + dy;
                int x = b[i] + dx;
                if (is_on_field(y, x) and not used.count(make_pair(y, x))) {
                    int cnt = 0;
                    used.emplace(y, x);
                    for (int dy2 : { 0, 1, 2 }) {
                        for (int dx2 : { 0, 1, 2 }) {
                            int y2 = y + dy2;
                            int x2 = x + dx2;
                            cnt += exists.count(make_pair(y2, x2));
                        }
                    }
                    if (cnt) {
                        ans[cnt] += 1;
                        ans[0] -= 1;
                    }
                }
            }
        }
    }
    // output
    repeat (i,10) cout << ans[i] << endl;
    return 0;
}
```
