---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/372/
  - /blog/2016/05/24/yuki-372/
date: 2016-05-24T22:02:21+09:00
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/598" ]
---

# Yukicoder No.372 It's automatic

これは星3だと思う。

## solution

DP。$O(\|S\|M)$。

文字列を左から見ていって、今見ている所より左側だけでできる部分列を、その$M$を法とした値ごとに分類したそれぞれの個数を更新していく。
横に答えとなる値を持っておいて、新しくできた$M$を法として$0$となる部分列の数を加えていく。
見る文字が$0$かそうでないかで軽い場合分け。
$\operatorname{dp}\_{\text{sum}} = \text{count}$。

## implementation

`int`で持って毎回剰余するのと`long long`に貯めてまとめて剰余とるのとで、2倍以上の速度差がでた。
以下は遅い方。

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
const int mod = 1e9+7;
int main() {
    string s; int m; cin >> s >> m;
    vector<int> cur(m);
    vector<int> prv;
    int ans = 0;
    for (char c : s) {
        int d = c - '0';
        cur.swap(prv);
        cur.clear();
        cur.resize(m);
        repeat (i,m) {
            cur[i] += prv[i];
            cur[i] %= mod;
            cur[(i * 10 + d) % m] += prv[i];
            cur[(i * 10 + d) % m] %= mod;
            if ((i * 10 + d) % m == 0) {
                ans += prv[i];
                ans %= mod;
            }
        }
        if (d == 0) {
            ans += 1;
            ans %= mod;
        } else {
            cur[d % m] += 1;
            cur[d % m] %= mod;
            if (d % m == 0) {
                ans += 1;
                ans %= mod;
            }
        }
    }
    cout << ans << endl;
    return 0;
}
```
