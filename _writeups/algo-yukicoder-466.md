---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/466/
  - /blog/2016/12/19/yuki-466/
date: "2016-12-19T23:48:35+09:00"
tags: [ "competitive", "writeup", "yukicoder", "coordinate-compression" ]
"target_url": [ "http://yukicoder.me/problems/no/466" ]
---

# Yukicoder No.466 ジオラマ

コーナーケースきっちり潰されてて涙目になった。
よくできてる問題だけどきらい。

## solution

気合いで構成。$O(N)$。

-   $d$は忘れて、最後に確認すればよい。
-   $a = b = c \ge 2$のときは閉路を作ればよい。
-   $a = b = c = 1$のときは$d$に関わらず作れない。
-   $c = 0$のときは直線が$2$本。
-   $a \ne c \lor b \ne c$かつ$c \ge 1$のときは以下の図の形。
    -   $a = c \lor b = c$のとき、対応する分岐が潰れて直線になる。

```
    0       1
     \     /
      \   /
       \ /
        Y
        |
        |
        |
    図1. 基本形
```

indexを雑に作ってから座圧っぽく振り直すと楽。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <map>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
int main() {
    int a, b, c, d; cin >> a >> b >> c >> d;
    bool impossible = false;
    vector<pair<int, int> > e;
    if (a == c and b == c) {
        if (c == 1) {
            impossible = true;
        } else {
            repeat (i,c) e.emplace_back(i, (i+1)%c);
        }
    } else {
        int A = 1000000;
        int B = 2000000;
        int C = 3000000;
        map<int,int> tr;
        if (c == 0) {
            repeat (i,a-1) e.emplace_back(A+i, A+i+1);
            repeat (i,b-1) e.emplace_back(B+i, B+i+1);
        } else {
            repeat (i,a-c) e.emplace_back(A+i, A+i+1);
            repeat (i,b-c) e.emplace_back(B+i, B+i+1);
            repeat (i,c-1) e.emplace_back(C+i, C+i+1);
            if (a == c) A = C;
            if (b == c) B = C;
            tr[A+a-c] = C;
            tr[B+b-c] = C;
        }
        map<int,int> compress;
        compress[A] = 0;
        compress[B] = 1;
        auto name = [&](int & i) {
            if (tr.count(i)) i = tr[i];
            if (not compress.count(i)) { int size = compress.size(); compress[i] = size; }
            i = compress[i];
        };
        for (auto & it : e) {
            name(it.first);
            name(it.second);
        }
    }
    if (impossible or e.size() > d) {
        cout << -1 << endl;
    } else {
        cout << a+b-c << ' ' << e.size() << endl;
        for (auto it : e) cout << it.first << ' ' << it.second << endl;
    }
    return 0;
}
```
