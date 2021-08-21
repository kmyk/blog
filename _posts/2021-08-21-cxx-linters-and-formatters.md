---
category: blog
layout: post
---

# 競技プログラミングでも linter と formatter を使おう

## linter: `clang-tidy`

[`clang-tidy`](https://clang.llvm.org/extra/clang-tidy/index.html) は clang を利用した C++ の linter です。
C++ コードを分析して、ありがちなミスを指摘してくれます。

たとえば以下のようなコードを考えましょう。
このように書いた `std::lower_bound` は `xs` の大きさ $N$ に対し $O(\log N)$ ではなく $O(N)$ かかるという事実は有名ですが、慣れないうちは気付かずうっかりこのように書いてしまうこともあるでしょう (詳細: [std::lower_bound の罠について - えびちゃんの日記](https://rsk0315.hatenablog.com/entry/2019/09/10/173708))。

``` c++
#include <algorithm>
#include <set>
#include <iostream>
int main() {
    std::set<int> xs { 1, 2, 5, 8 };
    auto it = std::lower_bound(xs.begin(), xs.end(), 3);
    std::cout << *it << std::endl;
}
```

`clang-tidy` はこのようなミスを自動で検出し報告してくれます。
パフォーマンス関連の警告を有効にするために `-checks=perf\*` オプションを付けて `$ clang-tidy -checks=perf\* main.cpp` と実行すると、以下のように表示が出ます。

``` console
$ clang-tidy -checks=perf\* main.cpp
...
/home/ubuntu/main.cpp:6:15: warning: this STL algorithm call should be replaced with a container method [performance-inefficient-algorithm]
    auto it = std::lower_bound(xs.begin(), xs.end(), 3);
              ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
              xs.lower_bound(3)
...
```

しかも `-fix` オプションを付けて実行すれば修正まで自動でやってくれます。

通常のコンパイル時の警告より詳しくパフォーマンスの警告が表示されるだけで特に邪魔にはならないので、とりあえず使っておくとよいのではないでしょうか。

## formatter: `clang-format`

[`clang-format`](https://clang.llvm.org/docs/ClangFormat.html) は clang を利用した C++ の formatter です。
C++ のコードを整形してくれます。

たとえば以下のようなコードを考えましょう。
フォーマットがここまで崩壊したコードを書く人はそういないでしょうが、ブレース (`{`, `}`) を伴わない for 文などでうっかりミスをする初心者はいないとも限りません。

``` c++
#include <iostream>
#include <vector>
using namespace std;
int i, j, k;
int main() {
int n;
    cin >> n;
   vector<int> a(n),b(n);
    for (int i =0; i<n; ++i)
            cin >> a[i];
            cin >> b[i];
cout << b[0]<<endl;
}
```

このようなコードを `clang-format` に与えると、以下のようにフォーマットを整えたものを出力してくれます。

``` console
$ clang-format main.cpp
#include <iostream>
#include <vector>
using namespace std;
int i, j, k;
int main() {
  int n;
  cin >> n;
  vector<int> a(n), b(n);
  for (int i = 0; i < n; ++i)
    cin >> a[i];
  cin >> b[i];
  cout << b[0] << endl;
}
```

また、`-i` オプションを付けるとそのままファイルに書き込んでくれます。

フォーマットの設定は詳細に可能です。
たとえば、インデントの幅を 4 にしたいときは `IndentWidth: 4` を、長い行の折り返しをなしにしたいときは `ColumnLimit: 9999` を、REP マクロを認識してほしいときは `ForEachMacros: ["REP", "REP3"]` などを、`-style` オプション経由で渡し、`$ clang-format -style='{IndentWidth: 4, ColumnLimit: 9999, ForEachMacros: ["REP", "REP3"]}' main.cpp` のようにします。
詳しくは[ドキュメント](https://clang.llvm.org/docs/ClangFormatStyleOptions.html)を読みましょう。

手動で常にきちんとフォーマットを整えられる人には formatter はまったく不要 (というか邪魔) だと思いますが、そうでない初心者などは自動でフォーマットを整えてもらうよう設定しておく (例: エディタで保存するたびに `clang-format` が実行されるようにしておく) とよいでしょう。

## まとめ

-   `clang-tidy` を使いましょう。パフォーマンス関連のミスも警告してくれるので、競プロにおいても役立ちます。
-   `clang-format` は好みにあわせて使ったり使わなかったりしましょう。競プロにおいてはあまり要らない気はします。
