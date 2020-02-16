---
layout: post
redirect_from:
  - /blog/2016/04/24/jag2016-domestic-a/
date: 2016-04-24T22:28:23+09:00
tags: [ "competitive", "writeup", "atcoder", "jag", "icpc" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2016-domestic/tasks/jag2016secretspring_a" ]
---

# JAG Contest 2016 Domestic A - 阿吽の呼吸

本番はチームのメンバーに任せた。
後から自分で解いたら誤読した。

## problem

`A` `Un`をそれぞれ`(` `)`で置き換えたとき、対応が取れているか答えよ。

## implementation

``` c++
#include <iostream>
using namespace std;
int main() {
    int n; cin >> n;
    int dangling_a = 0;
    bool unneeded_un = false;
    while (n --) {
        string s; cin >> s;
        if (s == "A") {
            ++ dangling_a;
        } else if (s == "Un") {
            if (dangling_a) {
                -- dangling_a;
            } else {
                unneeded_un = true;
            }
        }
    }
    cout << (dangling_a or unneeded_un ? "NO" : "YES") << endl;
    return 0;
}
```
