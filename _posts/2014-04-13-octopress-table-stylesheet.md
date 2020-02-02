---
category: blog
layout: post
title: "octopressのtableのstylesheet設定した"
date: 2014-04-13T16:19:23+09:00
tags: [ "octopress", "blog", "table", "stylesheet", "css", "scss" ]
---

[Octopress Table Stylesheet - Junda Ong](http://samwize.com/2012/09/24/octopress-table-stylesheet/)のを加工&配置のmemo

<!-- more -->

1.  cssを貰ってくる
2.  selectorに問題があるので修正
3.  修正後のを配置する

## 入手
[上で挙げたページ](http://samwize.com/2012/09/24/octopress-table-stylesheet/)から[gist](https://gist.github.com/programus/1993032#file-data-table-css)へ行ってcssを貰う

## 修正

### 動機
selectorが全て以下のようになっている

``` css
* + table { ... }
```

`なにか要素があって、その要素の次のtableに対して`ぐらいの意味 ([隣接セレクタ \- CSS \| MDN](https://developer.mozilla.org/ja/docs/Web/CSS/Adjacent\_sibling\_selectors))  
code-blockに`<table>`が使われているのでそのため  
しかし記事の冒頭の表に対して適用されないので修正する

ついでにheaderをかっこ良くした

### 結果
``` scss
div.entry-content > table, div.entry-content div:not(.highlight) > table {

    border-style:solid;
    border-width:1px;
    border-color:#e7e3e7;

    th, td {
        border-style:dashed;
        border-width:1px;
        border-color:#e7e3e7;
        padding-left: 3px;
        padding-right: 3px;
    }

    th {
        border-style:solid;
        font-weight:bold;
        @include background($nav-bg-front, $nav-bg-back);
    }

    th[align="left"],   td[align="left"]   { text-align:left; }
    th[align="right"],  td[align="right"]  { text-align:right; }
    th[align="center"], td[align="center"] { text-align:center; }

}
```

最外のselectorは`各記事のrootの(直下の | 中の、highlight-classの直下にない)table`の意  
できるだけ範囲を限定したかったので`div.entry-content`制約加えた

table-headerはnavやfooterの設定をコピーして、グラデーションかけた

## 配置
`@include background(...);`したため、これらをスコープに入れる必要が有るので、  
上のscssを`$OCTOPRESS/sass/custom/_styles.scss`に追記する

この行に変更を加えず元のままにしておくなら、これを`$OCTOPRESS/sass/data-table.scss`に配置し、元記事のように`<link>`を加えれば良い
