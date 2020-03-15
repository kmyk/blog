---
category: blog
layout: post
redirect_from:
    - "/blog/2016/07/03/s-octopress-hugo/"
date: "2016-07-04T03:17:08+09:00"
tags: [ "blog", "octopress", "hugo" ]
---

# OctopressからHugoに移行した

-   [Octopress](http://octopress.org/)
-   [Hugo](http://gohugo.io/)

blog frameworkの移行をした。

## pros

-   処理の高速化
    -   $600$記事に対し$2700$秒($45$分)かかっていたのが$15$秒になった
-   blogのソースコードがシンプルになった
    -   おまじないになってしまっているファイルがほぼない
-   install/updateが楽
    -   ubuntuだと`apt install hugo`で済む
    -   octopressだと`git clone git://github.com/imathis/octopress.git octopress`して`bundle --path vendor/bundle`

## cons

-   syntax highlightの質が下がった
    -   parseに失敗してるのが見られる
    -   行番号の表示ができなくなった
    -   highlight.jsを採用した
-   `atom.xml`が消える
    -   `index.xml`(RSS)を`cp`して誤魔化した
-   機能が弱い/分かりにくい
    -   特に、github pagesへのdeployのscriptを自分で書かないといけない
-   既存themeを(参考にはしたが)使わずscratchしたらデザインがだめになった
    -   なんだか少し古い感じがしてしまう 何故なのか

## まとめ

一長一短あるように感じた。

今からblogを始めるとしても、記事のcompileが$2,3$分ぐらいで済むような使い方をするなら予定ならoctopressは十分妥当な選択肢だろうし、既にoctopressで運用をしている場合、compileが$7,8$分程度で済んでいるならわざわざ移行する必要はないだろう。
記事の投稿に$1$分$1$秒を争うような事態なんてそうそうないと思いませんか。

また、速いとは言っても、概算して$2.5$秒/$100$記事である。
月$50$記事増えるとすると$1$年ごとに処理時間が$30$秒増える計算になる。
無料/有料のblog serviceへの移行も考慮すべきだったかもしれない。
