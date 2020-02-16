---
layout: post
alias: "/blog/2017/12/31/utpc-2012-f/"
date: "2017-12-31T17:56:03+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "rolling-hash", "collision", "birthday-attack" ]
"target_url": [ "https://beta.atcoder.jp/contests/utpc2012/tasks/utpc2012_06" ]
---

# 東京大学プログラミングコンテスト2012: F - Uinny

## solution

誕生日攻撃。$O(\sqrt{b})$。

同じhash値を持つ文字列の組$(s\_1, s\_2), (t\_1, t\_2)$があり、$t\_1, t\_2$の長さが等しい(あるいは$s\_1$のhash値が空文字列のhash値に等しい)ならば、連結して$4$通りの$s\_i t\_j$のhash値は全て等しい。
このような組を$7$つ集めれば$2^7 = 128 \ge 100$個の文字列が作れるので満点が得られる。
$7 \times 7 = 49 \le 50$と設定されているので文字列の長さを$7$に固定して誕生日攻撃をすればよい。
あるいはhashの初期値(つまり空文字列のhash値)を$0$以外に動かせるように拡張すれば繰り返し誕生日攻撃をすることになるが長さの固定の必要はなくなる。

注意としては文字列はちゃんと乱数で生成すること。
`aaaaaaa`から`zzzzzzz`に向かってincrementなどとすると偏りが生じて計算量が増える。
また、$7$文字固定なら実質無視できるが、同じ文字列が複数回生成されてしまう場合や異なる文字列辺の列を連結した結果がたまたま一致してしまう場合にも注意。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using ll = long long;
using namespace std;

int main() {
    // input
    int a, b; cin >> a >> b;
    // solve
    auto hash = [&](string const & s) {
        ll h = 0;
        for (char c : s) {
            h = (h * a + (c - 'a' + 1)) % b;
        }
        return h;
    };
    vector<pair<string, string> > collision;
    default_random_engine gen;
    unordered_map<int, string> found;
    while (true) {
        string s;
        REP (i, 7) s += uniform_int_distribution<char>('a', 'z')(gen);
        int h = hash(s);
        if (found.count(h) and found[h] != s) {
            collision.emplace_back(s, found[h]);
            found.erase(h);
            if (collision.size() == 7) break;
        } else {
            found[h] = s;
        }
        // pred
        if (s == "zzzzzzz") break;
        // increment
        int i = 0;
        while (s[i] == 'z') s[i ++] = 'a';
        s[i] += 1;
    }
    // output
    REP (x, 100) {
        string s = "";
        REP (i, 7) {
            s += (x & (1 << i) ? collision[i].first : collision[i].second);
        }
        cout << s << endl;
    }
    return 0;
}
```
