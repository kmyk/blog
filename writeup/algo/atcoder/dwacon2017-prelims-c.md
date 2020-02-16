---
layout: post
redirect_from:
  - /blog/2016/12/17/dwacon2017-prelims-c/
date: "2016-12-17T22:04:45+09:00"
tags: [ "competitive", "writeup", "atcoder", "dwacon" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2017-prelims/tasks/dwango2017qual_c" ]
---

# 第3回 ドワンゴからの挑戦状 予選: C - スキーリフトの相乗り

## solution

順番は無視してよい。入力$O(N)$だが計算$O(1)$。

あるグループの集合$\\{ i, j, \dots \\}$をまとめてひとつのリフトに載せたいとする。
これらグループの内最も前に並んでいるグループが先頭に来たタイミングで、他のグループを案内すればよい。
つまり、待ち行列に関する制約は全て考える必要がない。

後はいい感じに組を作ればよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    int ans = 0;
    array<int,5> cnt = {}; repeat (i,n) cnt[a[i]] += 1;
    ans += cnt[4]; cnt[4] = 0;
    ans += cnt[3]; cnt[1] = max(0, cnt[1] - cnt[3]); cnt[3] = 0;
    ans += cnt[2] / 2; cnt[2] %= 2;
    if (cnt[2] == 1) {
        ans += 1;
        cnt[2] = 0;
        cnt[1] = max(0, cnt[1] - 2);
    }
    ans += (cnt[1] + 3) / 4; cnt[1] = 0;
    cout << ans << endl;
    return 0;
}
```
