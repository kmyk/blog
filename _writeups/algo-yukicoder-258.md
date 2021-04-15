---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/258/
  - /blog/2016/10/18/yuki-258/
date: "2016-10-18T20:22:27+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp", "path-reconstruction" ]
"target_url": [ "http://yukicoder.me/problems/no/258" ]
---

# Yukicoder No.258 回転寿司(2)

解説tabを開いたら後輩氏の解説へのlinkがあった。頑張ってるなあ。

## solution

DPして経路復元。$O(N)$。元の漸化式が単純なので表から直接復元すればよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <deque>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int n; cin >> n;
    vector<int> v(n); repeat (i,n) cin >> v[i];
    vector<int> dp(n+1);
    dp[0] =    0;
    dp[1] = v[0];
    repeat_from (i,1,n) {
        dp[i+1] = max(dp[i], dp[i-1] + v[i]);
    }
    deque<int> used;
    for (int i = n; ;) {
        if (i == 0) {
            break;
        } else if (i == 1) {
            used.push_front(0);
            break;
        } else {
            if (dp[i] == dp[i-2] + v[i-1]) {
                used.push_front(i-1);
                i -= 2;
            } else {
                i -= 1;
            }
        }
    }
    cout << dp[n] << endl;
    for (int i : used) cout << i+1 << ' '; cout << endl;
    return 0;
}
```
