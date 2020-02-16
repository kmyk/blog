---
layout: post
redirect_from:
  - /blog/2018/01/05/arc-069-d/
date: "2018-01-05T23:34:41+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc069/tasks/arc069_b" ]
---

# AtCoder Regular Contest 069: D - Menagerie

## solution

列$t$のうち連続する$2$点を決めれば再帰的に残りも決まる。この始点の決め方を$4$通り全て試す。$O(N)$。

制約を整理すると$s, t$をbit列と見て$s\_i \oplus t\_{i - 1} \oplus t\_i \oplus t\_{i + 1} = 0$という排他的論理和による式が得られる。
これを使うと実装がちょっとだけ楽になる。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
using namespace std;

vector<bool> solve(int n, vector<bool> const & s) {
    REP (t_0, 2) {
        REP (t_1, 2) {
            vector<bool> t(n);
            t[0] = t_0;
            t[1] = t_1;
            REP3 (i, 2, n) {
                t[i] = (t[i - 2] ^ t[i - 1] ^ s[i - 1]);
            }
            if (s[n - 1] == (t[n - 2] ^ t[n - 1] ^ t[0]) and
                    s[0] == (t[n - 1] ^ t[0] ^ t[1])) {
                return t;
            }
        }
    }
    return vector<bool>();
}

int main() {
    int n; cin >> n;
    vector<bool> s(n);
    REP (i, n) {
        char s_i; cin >> s_i;
        s[i] = (s_i == 'o');
    }
    vector<bool> result = solve(n, s);
    if (result.empty()) {
        cout << -1 << endl;
    } else {
        for (bool p : result) cout << (p ? 'S' : 'W');
        cout << endl;
    }
    return 0;
}
```
