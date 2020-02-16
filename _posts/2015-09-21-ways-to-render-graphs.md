---
category: blog
layout: post
date: 2015-09-21T09:24:41+09:00
tags: [ "graph", "graph-theory", "graphviz", "dot", "tex", "latex", "tikz", "xypic", "svg" ]
---

# グラフとかを出力する方法いろいろ

グラフ理論の意味でのグラフを出力する/できるツールたちの紹介。

グラフを並べて観察したい -> ちょうどtexでグラフ書いてたところだったのでlatex+xypicを`system(3)`から使う $\to$ 1000個単位でpngを生成するには遅すぎて色々探す、などした結果のまとめ。
グラフをひとつ固定してその部分グラフばかり考えていたので、(自動レイアウトだと目的からずれるため)わりと汎用的。競技プログラミングで幾何の問題解いてる時にも使えそう。

<!-- more -->

## graphviz

DOT言語で表現されたグラフをpngやsvgとして描画してくれる。
もちろん自動でレイアウトしてくれる。
知る限り最も汎用的なツール。

逆に、頂点座標を指定するなどは基本的にできない。
レイアウトに不満があるならsvgで出力してinkscape等で修正すると良いようだ。

### DOT言語の例

``` plain
graph graphname {
    a -- b -- c;
    b -- d;
}
```

![](graphviz-y.svg)

``` plain
digraph graphname {
    a -> z;
    b -> z;
    c -> z;
    z -> a;
}
```

![](graphviz-w.svg)

``` plain
graph graphname {
    a -- b -- c -- d -- e -- f -- a;
    a -- c -- e -- a;
    b -- d -- f -- b;
    a -- d;
    b -- e;
    c -- f;
}
```

-   dot ![](graphviz-k6-dot.svg)
-   twopi ![](graphviz-k6-twopi.svg)
-   circo ![](graphviz-k6-circo.svg)

### 使用

たいていはコマンドから。`dot` `neato` `twopi` `circo` ... といったレイアウトに対応した名前のコマンドを叩く。

``` sh
$ dot -T svg foo.dot > foo.svg
$ neato -T svg foo.dot > foo.svg
$ circo -T svg foo.dot > foo.svg
```

c言語のライブラリとしても呼びだせる。

``` c
#include <graphviz/gvc.h>
int main(void) {
    GVC_t *gvc = gvContext();
    graph_t *g = agread(stdin, 0);
    gvLayout(gvc, g, "dot");
    gvRender(gvc, g, "svg", stdout);
    gvFreeLayout(gvc, g);
    agclose(g);
    gvFreeContext(gvc);
    return 0;
}
```

``` sh
$ cc -l gvc -l cgraph a.c
$ ./a.out < foo.dot > foo.svg
```

### 参考

-   [DOT言語 - Wikipedia](https://ja.wikipedia.org/wiki/DOT%E8%A8%80%E8%AA%9E)
-   [Graphviz - Wikipedia](https://ja.wikipedia.org/wiki/Graphviz)
-   <http://graphviz.org/>


## latex + tikz

手で直接書く場合や、数式を放り込みたい場合、座標を指定したい場合に。

グラフ特化ではなくてもう少し汎用的な道具。ちょっと遅い。
`\draw (0,0) grid (42,42);`が便利。
xypic含め可換図式とかも書ける。

``` sh
$ pdflatex -shell-escape foo.tex #=> foo.pdf & foo.png
$ pdf2svg foo.pdf foo.svg # optional
```

``` tex
\documentclass[png]{standalone}
\usepackage{tikz}
\begin{document}
\begin{tikzpicture}[every node/.style={circle,draw}]
    \node (A) at (14, 4) {};
    \node (B) at ( 7, 0) {};
    \node (C) at ( 0, 4) {};
    \node (D) at ( 0,12) {};
    \node (E) at ( 7,16) {};
    \node (F) at (14,12) {};
    \foreach \u \v in {A/B,A/C,A/D,A/E,A/F,B/C,B/D,B/E,B/F,C/D,C/E,C/F,D/E,D/F,E/F}
        \draw (\u) -- (\v);
\end{tikzpicture}
\end{document}
```

<img src="tikz-k6.svg" width="256" height="256">

### 参考

-   [TikZ 覚書](http://perikanfan.web.fc2.com/Manual.pdf)
-   <http://www.opt.mist.i.u-tokyo.ac.jp/~tasuku/tikz.html>
-   <http://tex.stackexchange.com/questions/121638/tex-figure-to-png>

## latex + xypic

tikzと似たもの。しかしtikzのほうがよいらしいと聞く。

``` tex
\documentclass[png]{standalone}
\usepackage[all]{xy}
\begin{document}
\begin{xy}
    (14, 4)*{\circ}="A",
    ( 7, 0)*{\circ}="B",
    ( 0, 4)*{\circ}="C",
    ( 0,12)*{\circ}="D",
    ( 7,16)*{\circ}="E",
    (14,12)*{\circ}="F",
    { "A" \ar @{-} "B" },
    { "A" \ar @{-} "C" },
    { "A" \ar @{-} "D" },
    { "A" \ar @{-} "E" },
    { "A" \ar @{-} "F" },
    { "B" \ar @{-} "C" },
    { "B" \ar @{-} "D" },
    { "B" \ar @{-} "E" },
    { "B" \ar @{-} "F" },
    { "C" \ar @{-} "D" },
    { "C" \ar @{-} "E" },
    { "C" \ar @{-} "F" },
    { "D" \ar @{-} "E" },
    { "D" \ar @{-} "F" },
    { "E" \ar @{-} "F" },
\end{xy}
\end{document}
```

<img src="xypic-k6.svg" width="256" height="256">

### 参考

-   <http://akagi.ms.u-tokyo.ac.jp/inputxy.pdf>

## .svg 直出力

直接書くのも難しくない。特に速度と容量の面で有利。でも多少の使い難さはある。

``` xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
 "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     width="160" height="180">
    <g transform="translate(10,10) scale(10,10)" fill="none" stroke="black" stroke-width="0.1">
        <path d="M 14  4 L  7  0" />
        <path d="M 14  4 L  0  4" />
        <path d="M 14  4 L  0 12" />
        <path d="M 14  4 L  7 16" />
        <path d="M 14  4 L 14 12" />
        <path d="M  7  0 L  0  4" />
        <path d="M  7  0 L  0 12" />
        <path d="M  7  0 L  7 16" />
        <path d="M  7  0 L 14 12" />
        <path d="M  0  4 L  0 12" />
        <path d="M  0  4 L  7 16" />
        <path d="M  0  4 L 14 12" />
        <path d="M  0 12 L  7 16" />
        <path d="M  0 12 L 14 12" />
        <path d="M  7 16 L 14 12" />
    </g>
</svg>
```

![](direct-k6.svg)


-   [svg要素の基本的な使い方まとめ](http://www.h2.dion.ne.jp/~defghi/svgMemo/svgMemo.htm)
-   [Static SVG tutorial - EduTech Wiki](http://edutechwiki.unige.ch/en/Static_SVG_tutorial)

## 他

他に調べたり検討したりしたやつ。

-   [boost::graph](http://www.boost.org/doc/libs/release/libs/graph/doc/index.html)
-   [igraph](http://igraph.org/)
-   [D3.js](http://d3js.org/)
