---
layout: post
alias: "/blog/2016/03/30/arc-048-b/"
date: 2016-03-30T14:55:13+09:00
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc048/tasks/arc048_b" ]
---

# AtCoder Regular Contest 048 B - AtCoderでじゃんけんを

pythonで書いたらTLE。
通している人もいるので定数倍の改善をすればよさそうだが、面倒なのでc++へ。

pypyがあったら通っていたかもだし、古い問題でも新しい言語使いたいです。

## 解法

ratingでsortする。同rating集団内ではそれぞれの手の数を数える。$O(N)$。

## 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
struct player_t { int rating, hand, index; };
bool operator < (player_t a, player_t b) { return a.rating < b.rating; }
int main() {
    int n; cin >> n;
    vector<player_t> a(n);
    repeat (i,n) {
        cin >> a[i].rating >> a[i].hand;
        a[i].hand %= 3;
        a[i].index = i;
    }
    sort(a.begin(), a.end());
    vector<vector<int> > ans(n, vector<int>(3));
    int j = 0;
    repeat (i,n+1) {
        if (i == n or a[j].rating < a[i].rating) {
            vector<int> hands(3);
            repeat_from (k,j,i) {
                hands[a[k].hand] += 1;
            }
            repeat_from (k,j,i) {
                ans[a[k].index][0] += j;
                ans[a[k].index][1] += n-i;
                ans[a[k].index][2] += -1;
                repeat (l,3) {
                    ans[a[k].index][l] += hands[(l + 1 + a[k].hand) % 3];
                }
            }
            j = i;
        }
    }
    repeat (i,n) {
        cout << ans[i][0] << ' ' << ans[i][1] << ' ' << ans[i][2] << endl;
    }
    return 0;
}
```
