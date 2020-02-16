---
layout: post
redirect_from:
  - /blog/2016/01/11/fhc-2016-qual-b/
date: 2016-01-12 9:00:00 +0900
tags: [ "competitive", "writeup", "facebook-hacker-cup" ]
---

# Facebook Hacker Cup 2016 Qualification Round High Security

## [High Security](https://www.facebook.com/hackercup/problem/1527664744192390/)

### 問題

$2 \times W$の盤面が与えられる。各マスは空きマスまたは障害物である。
ここに警備員を何人か配置する。
警備員は4方向に十分長いの視界を持っている。将棋の飛車だと思えばよい。
全ての空きマスを監視するとき、警備員は最低何人必要か。

### 解法

縦幅が$2$しかないので貪欲。
$O(W)$。
警備員の上下への視界が結果に影響するのは、左右に障害物を持つ空きマスに関してのみであることを使う。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
using namespace std;
void solve() {
    int n; cin >> n;
    array<string,2> s; cin >> s[0] >> s[1];
    s[0] = "X" + s[0] + "X";
    s[1] = "X" + s[1] + "X";
    int ans = 0;
    repeat (y,2) {
        for (int l = 1; l <= n; ++l) {
            if (s[y][l] == 'X') continue;
            int r = l+1;
            while (s[y][r] != 'X') ++ r;
            if (r-l == 1) continue;
            repeat_from (x,l,r) {
                if (s[(y+1)%2][x-1] == 'X' and s[(y+1)%2][x] == '.' and s[(y+1)%2][x+1] == 'X') {
                    s[(y+1)%2][x] = 'X';
                    break;
                }
            }
            repeat_from (x,l,r) s[y][x] = 'X';
            ans += 1;
            l = r;
        }
    }
    repeat_from (x,1,n+1) {
        if (s[0][x] == '.' or s[1][x] == '.') {
            ans += 1;
        }
    }
    cout << ans << endl;
}
int main() {
    int testcases; cin >> testcases;
    repeat (testcase, testcases) {
        cout << "Case #" << testcase+1 << ": ";
        solve();
    }
    return 0;
}
```
