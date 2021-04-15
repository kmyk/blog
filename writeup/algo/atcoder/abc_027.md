---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc_027/
  - /writeup/algo/atcoder/abc-027/
  - /blog/2015/09/23/abc-027/
date: 2015-09-23T16:58:25+09:00
tags: [ "atcoder", "abc", "competitive", "writeup" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc027/" ]
---

# AtCoder Beginner Contest 027

C,Dを解いてなかったので

<!-- more -->

## [C - 倍々ゲーム](https://beta.atcoder.jp/contests/abc027/tasks/abc027_c) {#c}

本番で解けなかったやつ。
終了後に「実験すればよかったのかあ」と思った記憶があった。
愚直解は書いてあったのでそれで実験した結果を見て書いたら通った。
証明はしてない。

問題がとてもbit感あったので本番中はずっとbitばかり考えていた記憶がある。入力が単一の整数の場合は実験すべきっぽい。

``` c++
#include <iostream>
#include <cstdint>
typedef uint64_t ll;
using namespace std;
bool f(ll x) {
    ll y = 1;
    ll e = 1;
    if (x == 1) return false;
    while (true) {
        e *= 4;
        y += e; if (x <= y) return true;
        y += e; if (x <= y) return false;
    }
}
int main() {
    ll n; cin >> n;
    cout << (f(n) ? "Takahashi" : "Aoki") << endl;
    return 0;
}
```


## [D - ロボット](https://beta.atcoder.jp/contests/abc027/tasks/abc027_d) {#d}

今日始めて開いた問題。分からなかったので[答え](http://www.slideshare.net/chokudai/abc027)を見ました。

1.  愚直に再帰すると$O(2^{\|S\|})$で死ぬ。
2.  命令をどこまで実行したかとロボットの位置でdpしても$O(\|S\|^2)$で部分点だけ。
3.  得点の変化について`+` `-`でなく`M`に注目する。`M`を決定したときに変化する得点は`M`より右にある`+` `-`の数のみで決まる。
4.  なので、前処理として後ろから累積和を取りながら捜査しておけば`+` `-`は以降陽には現れない。
5.  左側から貪欲に`>` `<`を定めていくと、`M+M-`や`M-M+`のようなケースで困る。

というところまで考えていた。しかし`M`(とそれを決定したときの変化量)をソートする、という発想はなかった。

`M`の決定を`M`を決定した時の影響の大きさの順で行う、と言えば自然であるので思い付くべきだった。左側からのみ決定していくのではなくて両側から決定するとどうなるか等は考えていたので後一歩か。


``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
int ctoi(char c) {
    return c == '+' ?  1 :
           c == '-' ? -1 : 0;
}
int main() {
    string s; cin >> s;
    int n = s.size();
    vector<ll> acc(n);
    acc[n-1] = ctoi(s[n-1]);
    for (int i = n-2; i >= 0; -- i) acc[i] = acc[i+1] + ctoi(s[i]);
    vector<ll> m;
    repeat (i,n) if (s[i] == 'M') m.push_back(acc[i]);
    sort(m.begin(), m.end());
    repeat (i, int(m.size() / 2)) m[i] *= -1;
    cout << accumulate(m.begin(), m.end(), 0) << endl;
    return 0;
}
```

テストケース生成器

``` sh
#!/bin/bash
c=M+-
while true ; do
    s=$( for i in $(seq $1) ; do echo -n ${c:$[$RANDOM%3]:1} ; done )
    if [ $[$(echo $s | tr -cd M | wc -c) % 2] -eq 0 ] ; then
        echo $s
        break
    fi
done
```

検証器

``` haskell
#!/usr/bin/env runhaskell

import Data.List
import Data.Maybe

main :: IO ()
main = getLine >>= print . fromJust . go 0

go :: Int -> String -> Maybe Int
go 0 [] = Just 0
go _ [] = Nothing
go x ('+' : s) = (+)      x <$> go x s
go x ('-' : s) = subtract x <$> go x s
go x ('M' : s) = listToMaybe . reverse . sort $ catMaybes [go (x + 1) s, go (x - 1) s]
go _ _ = undefined
```

ロボットへの命令列が例の言語ぽくて困る
