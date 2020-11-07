---
category: blog
layout: post
date: 2020-11-07T23:59:59+09:00
tags: [ "math", "competitive" ]
---

# 二分探索 二分法 違い


## TL;DR

-   狭義の「二分探索」は「ソート済み配列に対する探索アルゴリズム」
-   狭義の「二分法」は「連続関数に対する求根アルゴリズム」
-   競プロの「にぶたん」は「単調増加な述語に対する探索アルゴリズム」

「二分法」は求根アルゴリズムという色が強いもので、より緩やかな概念である「二分探索」の一種だと理解されているように見える。
明らかに二分法であるものを除いて、競プロだと常に「二分探索」と言っておけばよいだろう。

## 背景

競技プログラミングの界隈では、「二分探索」と「二分法」の違いについて言及されることがある。
しかしたいてい明確な説明がされることはなく、なかば神話的に「なにやら違うらしい」とだけ認識されている。
この記事は、そのような神話を明らかにするために書かれた。


## 狭義の「二分探索」 "binary search"

とりあえず英語版 Wikipedia を見よう[^wikipedia]。
説明の 1 段落目に「計算機科学において、binary search とはソート済み配列の中から対象となる要素の位置を探索するアルゴリズムである」とある。

> In computer science, binary search, also known as half-interval search,[1] logarithmic search,[2] or binary chop,[3] is a search algorithm that finds the position of a target value within a sorted array.[4][5] ……
>
> <https://en.wikipedia.org/wiki/Binary_search_algorithm>

つまり、狭義の「二分探索」は「ソート済み配列に対する探索アルゴリズム」である。
「二分探索」という語と同様の文脈で出現する語にはたとえば「線形探索」がある。


## 狭義の「二分法」 "bisection method"

これもとりあえず英語版 Wikipedia を見よう。
説明の 1 段落目に「数学において、bisection method とは求根法のひとつで、正の値を持つ点と負の値を持つ点が知られているような連続関数に適用できるものである」「この手法は "interval halving method" や "binary search method" や "dichotomy method" とも呼ばれる」とある。

> In mathematics, the bisection method is a root-finding method that applies to any continuous functions for which one knows two values with opposite signs. (中略) The method is also called the interval halving method,[2] the binary search method,[3] or the dichotomy method.[4]
>
> <https://en.wikipedia.org/wiki/Bisection_method>

つまり、狭義の「二分法」は「連続関数に対する求根アルゴリズム」である。
また、「二分法のことが「二分探索」と呼ばれることがある」とのことである。
「二分法」という語と同様の文脈で出現する語にはたとえば「ニュートン法」がある。


## 競プロの「にぶたん」

ここでは便宜上の区別のために、競プロで用いられる「二分探索」を「にぶたん」と書くことにする。

これは蟻本を見るのがよいだろう。
蟻本では、以下のように配列にも連続関数にも依存しない形で「二分探索」が導入され、これが「ソート列から値を探す」「解を仮定し可能か判定」「最小値の最大化」などの用途に使えることが説明されている。

> 二分探索とは、解の存在範囲を狭めていくことにより最適解を求める手法です。……
>
> [プログラミングコンテストチャレンジブック [第2版]　～問題解決のアルゴリズム活用力とコーディングテクニックを鍛える～](https://www.amazon.co.jp/dp/4839941068) (p. 128)

つまり、競プロの「にぶたん」は配列や連続関数に限ったものではないと考えてよいだろう。
競技プログラミングにおいての「にぶたん」は、「解を仮定し可能か判定」などのような語からも分かるように「$\forall n \in \mathbb{N}. \varphi(n) \to \varphi(n + 1)$ および $\exists n \in \mathbb{N}. \varphi(n)$ を満たす $1$ 変数述語 $\varphi(n)$ に対し $\min \lbrace n \in \mathbb{N} \mid \varphi(n) \rbrace$ を求めるアルゴリズム[^set]」として理解されているように思う。

浮動小数点数を扱うような「にぶたん」についても同様である。整数の「にぶたん」の場合と同様の述語を用いた理解ができる。これには上記の説明中の $\mathbb{N}$ を $\mathbb{Q}$ や $\mathbb{R}$ で取り替えればよい。

## 比較

競プロの「にぶたん」は、おそらくは狭義の「二分探索」を素直に一般化したものと言ってよいだろう。
実際に、$a_n = 1 \leftrightarrow \varphi(n)$ で定義されるような、$0, 1$ のみからなる長い配列 $a$ を考えれば[^ary]、我々の「にぶたん」は配列上の二分探索に帰着される。
このことから「にぶたん」を「二分探索」と呼ぶことは妥当であろう。
もちろん「二分探索」は「にぶたん」の一種である。
よって「にぶたん」と「二分探索」は (広義には) 同じものと考えてよいだろう。

狭義の「二分法」は求根アルゴリズムという色が強いように思われる。
また競プロの「にぶたん」を二分法に (つまり、連続関数の根を求めればよいという形に) 自然に帰着させられる場合は少ない。
よって「にぶたん」を「二分法」と呼ぶことはあまり推奨されないと言える。
一方で「二分法」を「二分探索」と呼ぶことはおそらく妥当である。

## 脚注

[^wikipedia]: 今回のような一般的な語についての英語版の Wikipedia を用いるのは妥当だろう。英語版 Wikipedia は日本語のブログ記事などよりよほど信用できるはずである。
[^set]: あるいは述語と集合の同一視を使って「upward closed で非空な set $X \subseteq \mathbb{N}$ に対し $\min X$ を求めるアルゴリズム」と言うこともできる。
[^ary]: あるいは $b_n = \begin{cases} 0 & (\lnot \varphi(n)) \cr 1 & (\varphi(n) \land (n = 0 \lor \lnot \varphi(n - 1))) \cr 2 & (\text{otherwise}) \end{cases}$ を満たすような配列 $b$ を考えれば
