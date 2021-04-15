---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/469/
  - /blog/2016/12/21/yuki-469/
date: "2016-12-21T16:53:50+09:00"
tags: [ "competitive", "writeup", "yukicoder", "rolling-hash" ]
"target_url": [ "http://yukicoder.me/problems/no/469" ]
---

# Yukicoder No.469 区間加算と一致検索の問題

writerをしました。testerはcamypaperさんがしてくれました。
[Advent Calendar Contest Advent Calendar 2016](http://www.adventar.org/calendars/1659)の$19$日目の問題でした。

これが始めての作問でした。
自分の作った問題の提出一覧を眺めるのは楽しいですね。
予想はできていたのですが$8$分でuwiさんに通されてしまったのはもう少し耐えてほしかったし、koyumeishiさんやrickyさんあたりからWAを奪えたのはよかったと思います。
テストケースを作っているときは多少緩くてもいいかなという気があり、たとえばhash衝突はわざわざ落としにいかなくてもいいかなと思っていたのですが、簡単に通されるのはくやしいと分かったので次はもっと丁寧に作ります。それでもそこそこ衝突してくれていたけど。

問題内容に関して、区間$2$つ指定して一致判定の方が自然だし(衝突は減るけど)そうしてもよかったかも。
難易度は星$3$と迷ったのですが、星$3 \to 4$の事後修正が頻発してたこともあり高い方に倒しておきました。しかし$3$でもよかったかもしれない。

## solution

(以下は解説tabに書いたものと同じ。検索性のため転記。)

rolling hashやzobrist hashといった性質のよいhash関数と累積和/segment treeを使う。$O(N + Q \log N)$。
ここで言う性質のよいhash関数$H$とは、ベクトル$x,y$と整数$k$に対し$H(x) + H(y) = H(x + y)$や$k \cdot H(x) = H(kx)$が成り立つ関数。
事前に各基本ベクトル$e_i$ ($e\_{i,j} = 1$で他は$0$なやつ)について$H(e_i)$を定めておき、これを$i$の順に並べて区間総和を取れるようにしておく。
数列$x$そのものは持たず$H(x)$を操作しかつ連想配列に貯めていけば、どちらのクエリも$O(\log N)$以内で答えられる。

今回はあまり意味がないが、segment treeに入れる演算を$a \star b = a \cdot e^l + b$のようにして動的にrolling hashするのも面白いだろう。
準同型暗号とかいうのと近い気がするので、(よく知らないが)名前だけ挙げておく。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <random>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;

const int L = 3;
const int m[L] = { 1000000007, 1000000009, 1000000021 };
vector<array<int, L> > generate_e(int n) {
    vector<array<int, L> > e(n);
    int b[L];
    random_device device;
    default_random_engine engine(device());
    repeat (i,L) {
        uniform_int_distribution<int> dist(0, m[i]-1);
        b[i] = dist(engine);
    }
    whole(fill, e[0], 1);
    repeat (i,n-1) repeat (j,L) e[i+1][j] = e[i][j] *(ll) b[j] % m[j];
    return e;
}

array<int, L> add(array<int, L> const & a, array<int, L> const & b) {
    array<int, L> c;
    repeat (i,L) c[i] = (a[i] +(ll) b[i]) % m[i];
    return c;
};
array<int, L> mul(array<int, L> const & a, int b) {
    array<int, L> c;
    repeat (i,L) c[i] = ((a[i] *(ll) b) % m[i] + m[i]) % m[i];
    return c;
};

int main() {
    int n, q; cin >> n >> q;
    assert (1 <= n and n <= 1000000);
    assert (1 <= q and q <= 100000);
    vector<array<int, L> > e = generate_e(n);
    vector<array<int, L> > acc(n+1);
    repeat (i,n) acc[i+1] = add(acc[i], e[i]);
    array<int, L> x = {};
    map<array<int, L>, int> f;
    f[x] = 0;
    repeat (t,q) {
        char c; cin >> c;
        if (c == '!') {
            int l, r, k; cin >> l >> r >> k;
            assert (0 <= l and l <  n);
            assert (l <  r and r <= n);
            assert (- 100 <= k and k <= + 100);
            x = add(x, mul(add(acc[r], mul(acc[l], -1)), k));
            if (not f.count(x)) f[x] = t+1;
        } else if (c == '?') {
            cout << f[x] << endl;
        } else {
            assert (false);
        }
    }
    return 0;
}
```
