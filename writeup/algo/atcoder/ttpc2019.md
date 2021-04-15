---
redirect_from:
  - /writeup/algo/atcoder/ttpc2019/
layout: post
date: 2019-08-31T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# 東京工業大学プログラミングコンテスト2019

<marquee scrollamount="30">
<font color=#ff0000>東</font>
<font color=#ff8000>京</font>
<font color=#ffff00>工</font>
<font color=#80ff00>業</font>
<font color=#00ff00>大</font>
<font color=#00ff80>学</font>
</marquee>

##  A. Next TTPC

はい

## B. okyoech

sed

## C. XOR Filling

貪欲ぽく

## D. 素数取りゲーム

1.  $O(N^2)$ 愚直書いたら通るでしょ。見るの素数だけだし
1.  微妙に間に合わない
1.  分からないので埋め込み

メモ:

-   <blockquote class="twitter-tweet" data-conversation="none"><p lang="ja" dir="ltr">D: isprimeの配列を持っておいて、2を引いても素数であり続ける回数を求める</p>&mdash; %20｜1953 (+31) (@henkoudekimasu) <a href="https://twitter.com/henkoudekimasu/status/1167732538321731584?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
    想定は偶奇性を使った貪欲らしい。「素数の差」「素数の和」はほとんど必ず偶数なの忘れないようにしたい

## E. N法陣

1.  剰余を取ったものを並べればよい

    ```
    0321
    1032
    2103
    3210
    ```
    
    とか
    

    ```
    00000
    11111
    22222
    33333
    44444
    ```
    
1.  同じ列同士での交換はある $2$ 行にしか影響しない

    例:
    

    ```
    00004
    11111
    22222
    33333
    44440
    ```
    
1.  そんな感じでやればできる
1.  <https://atcoder.jp/contests/ttpc2019/submissions/7224168>

## F. Road Construction


1.  Kruskal ぽく貪欲？ → 嘘っぽい
1.  要件を強連結成分分解する？ → してどうなる
1.  あっ 誤読 (要件は $w \to x$ と $y \to z$ のふたつだけ)
1.  それぞれ独立に移動する / 途中のある区間が重なる で場合わけする典型
1.  各点で $w, x, y, z$ との距離を持ち、そこから最適に $x, z$ の両方へ移動するときのコスト、$w, y$ の両方から移動してくるときのコストをいい感じにやればよい
1.  <https://atcoder.jp/contests/ttpc2019/submissions/7224908>

メモ:

-   誤読したままでも解けるのかな？ $Q$ 個の要件 $s_i \to t_i$ ($i \lt Q$) が与えられるのですべて繋がないとだめな場合
-   こういうときはまず各点 Dijkstra して、その和を初期値にして再度 Dijkstra すればよい。一般に $k$ 点でこれをやるときは合流の順序の全探索が必要で $2^k - 1$ 回の Dijkstra が必要そう。Bellman Ford とかをしてもどうせ現在の状態を持つ必要があって $2^k - 1$ はかかる
-   <blockquote class="twitter-tweet"><p lang="ja" dir="ltr">Fのs_i &lt; t_iは虹色にして動かしてほしかった</p>&mdash; 衛藤渚 (@eto_nagisa) <a href="https://twitter.com/eto_nagisa/status/1167729373174091777?ref_src=twsrc%5Etfw">August 31, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
     これ気付いてなかった

## メモ

-   遅刻参加したのでぜんぜん解けず

## リンク

-   <https://atcoder.jp/contests/ttpc2019>
