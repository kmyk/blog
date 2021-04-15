---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/449/
  - /blog/2016/11/24/yuki-449/
date: "2016-11-24T23:41:59+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/449" ]
---

# Yukicoder No.449 ゆきこーだーの雨と雪 (4)

スコアは有理数値かあなるほどなあと言いながら座圧したらWAして、よく見たら切り捨てだった。
怪しい考察で投げたら間に合ってしまい、さらに計算量を悪くしても通った。
知らなかった。

## solution

愚直にやれば通ってしまう。参加者の人数を$M$として$O(T \sum L_i + T M))$でよい。

同じ得点を持った別の参加者がいるような参加者の順位は聞かれないとしよう。
得点の最大値は$100 \sum L_i$だが、$O(T\sum L_i)$の愚直で間に合う。
binary indexed treeあたりを使えばもう少しましになる。

同じ得点を持った別の参加者がいる場合。
上に加え同点の参加者内での計算が必要で単純ではないが、愚直に`std::vector`等で管理して$O(T M)$で間に合う。

## 計測

テストケースが弱いのかなと思って検証した。
c++は速いので間に合うということだった。
雑計測だし環境によって変わってくるはずなので、具体的な数値は参考程度にしておくべき。

$N = 10^5$だと間に合うようだ。
`-O3 -mtune=native`まで付けてみても特に変化せず。

``` sh
$ cat a.cpp
#include <iostream>
#include <vector>
#include <algorithm>
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    int q; cin >> q;
    while (q --) {
        int b; cin >> b;
        cout << (whole(find, a, b) - a.begin()) << endl;
    }
    return 0;
}

$ g++ -std=c++11 -O2 a.cpp

$ ( n=50000 ; echo $n ; seq $n ; echo $n ; seq $n ) | time ./a.out > /dev/null
0.38s 3276KB

$ ( n=50000 ; echo $n ; seq $n ; echo $n ; yes $n | head -n $n ) | time ./a.out > /dev/null
0.69s 3032KB

$ ( n=100000 ; echo $n ; seq $n ; echo $n ; seq $n ) | time ./a.out > /dev/null
1.35s 3084KB
```

ついでに加算の場合も見てみた。累積和をとったりするのも意外とさぼれるのでは。
$N = 10^5$ではちょっとつらそうだが、$O(N^2)$で効いているので$N = 10^4$なら十分ありだろう。
`accumulate`を`for`に展開しても特に変わらず。

``` sh
$ cat a.cpp
#include <iostream>
#include <vector>
#include <numeric>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    int q; cin >> q;
    while (q --) {
        int b; cin >> b;
        cout << accumulate(a.begin(), a.begin()+b, 0ll) << endl;
    }
    return 0;
}

$ g++ -std=c++11 -O2 a.cpp

$ ( n=50000 ; echo $n ; seq $n ; echo $n ; seq $n ) | time ./a.out > /dev/null
0.70s 3028KB

$ ( n=50000 ; echo $n ; seq $n ; echo $n ; yes $n | head -n $n ) | time ./a.out > /dev/null
1.36s 3140KB

$ ( n=100000 ; echo $n ; seq $n ; echo $n ; seq $n ) | time ./a.out > /dev/null
2.78s 3332KB

$ ( n=5000 ; echo $n ; seq $n ; echo $n ; yes $n | head -n $n ) | time ./a.out > /dev/null
0.02s 3080KB
```

## implementation

始めはbinary indexed treeを使ってACしたが、削っても間に合った。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using namespace std;
template <typename T> T sortuniq(T xs) { whole(sort, xs); xs.erase(whole(unique, xs), xs.end()); return xs; }
template <typename T> int index(vector<T> const & xs, T x) { return whole(lower_bound, xs, x) - xs.begin(); }
int scoreof(int level, int solved) {
    assert (solved >= 1);
    return 50*level + 250*level/(4+solved);
}
int main() {
    // input
    int n; cin >> n;
    vector<int> level(n);
    repeat (i,n) cin >> level[i];
    int query; cin >> query;
    vector<string> name(query);
    vector<char> action(query);
    repeat (t,query) cin >> name[t] >> action[t];
    // prepare
    const int max_score = 100 * whole(accumulate, level, 0);
    vector<string> ids = sortuniq(name);
    int m = ids.size();
    // answer
    vector<int> solved(n);
    vector<int> score(m);
    vector<vector<int> > inv(max_score + 1);
    repeat (id,m) inv[0].push_back(id);
    repeat (t,query) {
        int id = index(ids, name[t]);
        int j = score[id];
        if (action[t] == '?') {
            int a = 0; repeat (i,j) a += inv[i].size();
            int b = inv[j].size() - (whole(find, inv[j], id) - inv[j].begin()) - 1;
            cout << m-a-b << endl;
        } else {
            inv[j].erase(whole(find, inv[j], id));
            int i = action[t] - 'A';
            solved[i] += 1;
            j = score[id] += scoreof(level[i], solved[i]);
            inv[j].push_back(id);
        }
    }
    return 0;
}
```
