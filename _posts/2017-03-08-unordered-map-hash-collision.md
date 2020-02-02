---
category: blog
layout: post
date: "2017-03-08T11:46:59+09:00"
title: "std::unordered_mapのhash衝突による速度低下をさせてみる"
tags: [ "hash", "unordered-map" ]
---

## 概要

C++には`std::unordered_map`としてhash tableによる連想配列がある。
これは挿入/取得ともに平均$O(1)$だが、最悪計算量は$O(N)$である。
この$O(N)$になる悪意ある入力を作成し速度の低下を確認した。

## 計測対象

今回、計測の対象とするコードは以下。長さ$n$の数列$a$を受けとり、histogram $f$を作り、整数$b$の出現回数を答える。これは通常$O(n)$である。

``` c++
#include <iostream>
#include <unordered_map>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
int main() {
    int n; cin >> n;
    unordered_map<ll, int> f;
    repeat (i,n) {
        ll a; cin >> a;
        f[a] += 1;
    }
    ll b; cin >> b;
    cout << f[b] << endl;
    return 0;
}
```

以下のようにして作った入力に対し、手元では$0.05$秒で動作した。

```
$ ( n=100000 ; echo $n ; for _ in `seq $[n+1]` ; do echo $RANDOM ; done ) > test/random.in

$ time ./a.out < test/random.in
2
./a.out < test/random.in  0.05s user 0.00s system 98% cpu 0.049 total
```

## 攻撃

`std::unordered_map`にはbucketを操作するmethod群があるので、これを使えば簡単に$O(N)$となる入力を作れる。
これらは`std::unordered_set`や`std::unordered_multi*`にも存在する。

``` c++
namespace std {
template <class Key, class T, ...>
class unordered_map {
    ...
    // Bucket interface
    size_type bucket_count() const;  // returns the number of buckets
    size_type max_bucket_count() const;  // returns the maximum number of buckets
    size_type bucket_size( size_type n ) const;  // returns the number of elements in specific bucket
    size_type bucket( const Key& key ) const;  // returns the bucket for specific key
};
}
```

これを使うと、衝突するような入力の生成コードは以下のようになる。

``` c++
#include <iostream>
#include <unordered_map>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
int main() {
    int m = 100000;
    ll i = 0;
    unordered_map<ll,int> f;
    repeat (iteration, m) {
        cerr << "bucket_count " << f.bucket_count() << " / size " << f.size() << endl;
        while (f.count(i) or f.bucket(i) != 0) ++ i;
        f[i] = i;
        cout << i << endl;
    }
    return 0;
}
```

``` c++
$ ./a.out > foo
bucket_count 1 / size 0
bucket_count 2 / size 1
bucket_count 5 / size 2
bucket_count 5 / size 3
bucket_count 5 / size 4
bucket_count 11 / size 5
bucket_count 11 / size 6
bucket_count 11 / size 7
bucket_count 11 / size 8
bucket_count 11 / size 9
bucket_count 11 / size 10
bucket_count 23 / size 11
bucket_count 23 / size 12
bucket_count 23 / size 13
bucket_count 23 / size 14
bucket_count 23 / size 15
bucket_count 23 / size 16
...
bucket_count 126271 / size 99996
bucket_count 126271 / size 99997
bucket_count 126271 / size 99998
bucket_count 126271 / size 99999
./a.out > foo  361.60s user 3.49s system 99% cpu 6:06.00 total

$ tail foo
7360336590
7360462861
7360589132
7360715403
7360841674
7360967945
7361094216
7361220487
7361346758
7361473029
```

$10^5$回の衝突であれば、`int32_t`では足りず、生成にも$6$分以上かかるようだ。

これを元に生成した入力を先のプログラムに食わせると$13.32$秒かかった。$260$倍遅くなっており、攻撃に成功している。
$10^5$倍遅くなることが期待されるがそうでないのは、通常の場合だと入出力で律速していたからだと推測できる(未確認)。

```
$ time ./a.out < test/malicious.in
1
./a.out < test/malicious.in  13.32s user 0.00s system 99% cpu 13.330 total
```

## 対策

### std::mapを使う

`std::map`を使えばどのような入力にも挿入/取得が$O(\log n)$である。
大きな入力に対しては一般に遅くなるが、この攻撃に対しては強くなる。

``` c++
#include <iostream>
#include <map>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
int main() {
    int n; cin >> n;
    map<ll, int> f;
    repeat (i,n) {
        ll a; cin >> a;
        f[a] += 1;
    }
    ll b; cin >> b;
    cout << f[b] << endl;
    return 0;
}
```

```
$ time ./a.out < test/random.in
2
./a.out < test/random.in  0.08s user 0.01s system 98% cpu 0.093 total
```

### hash関数を変える

hashの衝突をさせるためには利用されているhash関数の情報が必須である。
未指定では`std::hash`が用いられるが、これを別のものに差し替えれば回避できる。
ただしソースコードを公開している状況ではこれは意味を成さない。
このため、指定するhash関数に実行時に生成した乱数を持たせるとよい。

hash関数を変えることと`std::unordered_map`に与える引数を一貫して変化させるのは同じ結果を生むため、実装例としては以下のようになる。
こうすれば(`mask`の値がleakされない限り)安全である。

``` c++
#include <iostream>
#include <unordered_map>
#include <random>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
int main() {
    ll mask = random_device()();
    int n; cin >> n;
    unordered_map<ll, int> f;
    repeat (i,n) {
        ll a; cin >> a;
        f[a^mask] += 1;
    }
    ll b; cin >> b;
    cout << f[b^mask] << endl;
    return 0;
}
```

```
$ time ./a.out < test/malicious.in
1
./a.out < test/malicious.in  0.08s user 0.00s system 95% cpu 0.084 total
```

## 参考

-   [unordered_map談義 - Togetterまとめ](https://togetter.com/li/972024)
-   [競技プログラミングにおけるstd::unordered_*** - 競技プログラミングをするんだよ](http://nitcoder000.hatenablog.com/entry/2016/05/21/180023)
-   [No.3016 unordered_mapなるたけ落とすマン - yukicoder](http://yukicoder.me/problems/1148)
-   [gccのunordered_mapの実装を読んでみる | ψ（プサイ）の興味関心空間](https://ledyba.org/2014/05/11110853.php)
