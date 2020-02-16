---
category: blog
layout: post
date: "2018-04-27T19:52:25+09:00"
tags: [ "minimax", "alphabeta", "branch-and-bound", "binary-search" ]
---

# minimax法とその派生の一覧

minimax法の系列が良く分かってなかったので調べて整理した。
minimax自体は分かるのだが、その派生が多すぎて混乱があったため。

この手の話の最大手は[Chess Programming Wiki](https://chessprogramming.wikispaces.com/)に見えるのでlinkはこれに向けて貼った。
適切な教科書があればそれを出典としたいのだが、そのようなものを知らないためわざわざ自分で調べているため、できない。誰か良い本を紹介してほしい。

-   [minimax法](https://chessprogramming.wikispaces.com/Minimax)
    -   ゲーム木探索法。損失の最大値を最小化。お互いに最適に動くと仮定して最適値を全探索。
    -   対象とするゲームは二人[零和](https://en.wikipedia.org/wiki/Zero-sum_game)[交互](https://en.wikipedia.org/wiki/Sequential_game)ゲーム。その他の性質は基本的に要求しない。
    -   以下は基本的に全てminimax法の高速化である。
-   [negamax法](https://chessprogramming.wikispaces.com/Negamax)
    -   minimax法の実装手法。手番ごとに正負をひっくり返すことで実装の共通化をする。
    -   追加で[対称](https://en.wikipedia.org/wiki/Symmetric_game)ゲームでもある必要がある。
    -   以下で名前にprefixとして "nega" を持つalgorithmはすべてこれと同様の派生である。
-   [alpha-beta法](https://chessprogramming.wikispaces.com/Alpha-Beta)
    -   minimax法を改良したalgorithm。[分枝限定法](https://en.wikipedia.org/wiki/Branch_and_bound)を導入したもの。
    -   最大化したい側と最小化したい側が両方存在する分枝限定法なので下限alphaと上限betaを持つ。alphaとbetaの作る区間を探索窓と呼ぶ。
-   negaalpha法
    -   alpha-beta法の実装手法。negamax法と同様の修正をする。
    -   検索しても日本語の資料ばかりでてくる。alpha-beta法の記事中に[Negamax Framework](https://chessprogramming.wikispaces.com/Alpha-Beta#Implementation-Negamax%20Framework)という形での言及ならある。
-   [null window](https://chessprogramming.wikispaces.com/Null%20Window) search
    -   alpha-beta法を利用した技法。探索窓の幅を0にしてalpha-beta法をすると、区間内に値がないので範囲外の値が返ることがあるが、探索窓の位置より真の値が上か下かは分かるというもの。探索窓の幅が広い場合より当然高速。
    -   [zero-window search](https://en.wikipedia.org/wiki/MTD-f#Zero-Window_Searches)など名前に揺れがある。
-   [negaC\*](https://chessprogramming.wikispaces.com/NegaC%2A)
    -   minimax法と同じ結果を得るalgorithm。null window search を用いて[二分探索](https://en.wikipedia.org/wiki/Binary_search_algorithm)をするもの。
    -   元々は単に C\* というのがあり、negamaxの風味を加えたものが negaC\* である。
-   [fail-soft](https://chessprogramming.wikispaces.com/Fail-Soft)
    -   alpha-beta法に加える修正。子を試した結果が探索窓の範囲外だった場合に、窓の境界値でなく実際に出てきた値を返すようにする。
-   [negascout](https://chessprogramming.wikispaces.com/NegaScout)
    -   alpha-beta法を改良したalgorithm。
    -   遷移を評価が良さそうな順に並べ、最も良さそうなものについて探索して結果を得て、残りについてはzero-window searchをしてその結果より悪いことを確認する。
        確認の結果より良い遷移があればその遷移を元の探索窓で再度探索し修正をする。
    -   knapsack問題を分枝限定法で解くときは「大きい方から試していく」「線形緩和解を上限とする」のが普通だが、これと似たものと思えばよさそう。
    -   [principal variation search](https://chessprogramming.wikispaces.com/Principal%20Variation%20Search) とは厳密には違うらしい。英[Wikipedia](https://en.wikipedia.org/wiki/Principal_variation_search)では実質的に同義として書いてる。もしかしたら上の文章も逆になってたりするかも。
    -   元々は単に scout という名前で導入され、negamaxによって拡張され negascout となった。
-   [MTD-f](https://chessprogramming.wikispaces.com/MTD%28f%29)
    -   minimax法と同じ結果を得るalgorithm。minimax法の推定値を使ってzero-window searchをすることを繰り返す。
    -   推定値が正しければzero-window searchでその値は不変。そうでなければもとの推定値より真の値に近い値が得られるのでこれで推定値を修正。
    -   [反復法](https://en.wikipedia.org/wiki/Iterative_method)のひとつ。[Newton法](https://en.wikipedia.org/wiki/Newton%27s_method_in_optimization)を思い出せばよい。

なお [minimax theorem](http://mathworld.wolfram.com/MinimaxTheorem.html) は[同時](https://en.wikipedia.org/wiki/Simultaneous_game)ゲームについての双対定理なので別物。

