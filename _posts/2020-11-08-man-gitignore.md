---
category: blog
layout: post
date: 2020-11-08T23:59:59+09:00
tags: [ "git" ]
---

# gitignore を正しく理解したい


## 目次

* TOC
{:toc}

## gitignore とは何であるか

gitignore ファイルは、意図的に track されていないファイルを指定しそれらを Git に無視させるためのファイルです。
このことは公式のリファレンス (<https://git-scm.com/docs/gitignore>) に次のような形で書かれています。

> NAME
>
> gitignore - Specifies intentionally untracked files to ignore

> DESCRIPTION
>
> A gitignore file specifies intentionally untracked files that Git should ignore. Files already tracked by Git are not affected; see the NOTES below for details.

ただし、ここで言う "gitignore" は、リポジトリのルートに置かれたあの `.gitignore` file のみのことではありません。
`$XDG_CONFIG_HOME/git/ignore` (Linux では `~/.config/git/ignore`) および `$GIT_DIR/info/exclude` (たいていの場合 `.git/info/exclude`) および (リポジトリのルートに限らない様々な場所にある) `.gitignore` のことを総称して "gitignore" と呼びます。
実際、"gitignore" と題された公式のリファレンスの冒頭は次のようになっています。

> SYNOPSIS
>
> `$XDG_CONFIG_HOME/git/ignore`, `$GIT_DIR/info/exclude`, `.gitignore`


## gitignore とは何のためのものか

Git に勝手に `git add` されたくないファイルや、そもそも「track されていない」と表示されてさえほしくないファイルがあれば、これを無視するために使うとよいでしょう。
これは公式のドキュメントである Pro Git book で紹介されている用法です。
"2.2 Git Basics - Recording Changes to the Repository" (<https://git-scm.com/book/en/v2/Git-Basics-Recording-Changes-to-the-Repository#_ignoring>) には次のようにあります。

> Ignoring Files
>
> Often, you’ll have a class of files that you don’t want Git to automatically add or even show you as being untracked. These are generally automatically generated files such as log files or files produced by your build system. In such cases, you can create a file listing patterns to match them named `.gitignore`.


## gitignore は「ファイルを track されていない状態に変えるもの」ではない

「gitignore ファイルは、ファイルを track されていない状態にするためのものである」という説明は不正確です。
gitignore ファイルは「track されていない状態のファイルを無視させる」あるいは同じことだが「track されていない状態のファイルを track されていない状態に保つ」機能を持ちます。しかし「すでに track されている状態のファイルを track されていない状態に戻す」のような機能は持ちません。

gitignore について表面的にのみ解説している説明はたいていこの区別について曖昧に (おそらくこの区別を理解せずに) 書かれています。そのような説明の例としては次があります。

> まずはgitignoreとは何かについて知っておきましょう。gitignoreはGitで使われる特殊なファイル名で、このファイルに書かれたファイルは上から順に処理されて、Gitのトラッキングの対象外になります。
>
> <a href="https://www.sejuku.net/blog/72389" rel="nofollow">gitignoreを設定して無視するファイルを指定しよう | 侍エンジニア塾ブログ（Samurai Blog） - プログラミング入門者向けサイト</a>[^sejuku]

多くの人がこの不適切な説明に混乱させられていることは、「[gitignore](https://www.google.com/search?q=gitignore)」で Google 検索をすると「[gitignore あとから](https://www.google.com/search?q=gitignore+%E3%81%82%E3%81%A8%E3%81%8B%E3%82%89)」というフレーズがサジェストされる[^suggest]ことから察せられます。
「gitignore あとから」というフレーズが多く検索されることの説明として「gitignore がファイルを track されていない状態に変える機能だと理解されているからだ」という説明は自然であるためです。

なお、この「ファイルを track されていない状態に変える」という目的で使うべき機能は `git rm` です。


## ファイルを track されていない状態に保ちたいだけなら `git add` しなければよい

`foo.txt` というファイルと `bar.txt` というファイルがあり、共に新規に作成したものであり共に track されていないとします。このとき `foo.txt` だけを commit に含めるにはどうすればよいでしょうか？ これはもちろん `$ git add foo.txt` とすればよいです。`.gitignore` に `bar.txt` という行を追加する必要はありません。

`.gitignore` が (実際には必須でない機能であるにも関わらず) ほとんど必須のものとして理解されている背景として、ファイルを index に追加するための機能として多くの人が `$ git add .` というやり方以外を知らない (ファイルを個別に index に追加するという発想がない) ことが予想されます。
しかし `$ git add .` はあまり丁寧なコマンドとは言えません。
「手元で実験用に書いたスクリプト (認証情報などを含む) が間違えて commit に含まれてしまっていたが、気付かず push してしまった」という状況はたまに見かけます。
何が commit に含まれるのかは `$ git status` や commit message の編集画面などで確認できるので、注意しながら commit を作りましょう。


## `$XDG_CONFIG_HOME/git/ignore` と `$GIT_DIR/info/exclude` と `.gitignore` をどう使いわけるべきか

使い分けについても、公式のリファレンス (<https://git-scm.com/docs/gitignore>) にあります。
以下のようなことが書かれています。

-   バージョン管理され `git clone` によって共有されるべきパターン (つまり、すべての開発者が無視したいと思うようなパターン) は `.gitignore` ファイルに書くべきです。
-   特定のリポジトリに固有であるが他の開発者と共有する必要のないパターン (たとえば、ひとりのユーザのワークフローに特有の補助的なパターン) は `$GIT_DIR/info/exclude` に書くべきです。
-   あるユーザがすべての状況で無視したいようなパターン (たとえば、そのユーザの利用しているエディタによって生成されるバックアップファイルや一時ファイルについてのパターン) は `$XDG_CONFIG_HOME/git/ignore` に書くべきです。



## 必ずしも `core.excludesfile` を指定する必要はない

グローバルな gitignore を利用するために `core.excludesfile` を指定する必要はありません。
そのデフォルト値である `$XDG_CONFIG_HOME/git/ignore` を使えばよいためです。
これはたいていは `$HOME/.config/git/ignore` に一致します。
また `$XDG_CONFIG_HOME` が未設定の場合にも `$HOME/.config/git/ignore` が用いられます。

`core.excludesfile` を利用した説明は多く見られますが、それらは「`$XDG_CONFIG_HOME/git/ignore` が追加される前に書かれた古い文章である」「`$XDG_CONFIG_HOME` の値が何であっても動作するようにするため、`$XDG_CONFIG_HOME` に依存しない方法を意図的に選んで紹介している」「古いバージョンの `git` コマンドでも動作するようにするため、古くからある機能を意図的に選んで紹介している[^version]」「他の文章をあまり理解せずそのままコピペしてきて書かれた」のいずれかでしょう。
たとえば Pro Git book ([Git - Git の設定](https://git-scm.com/book/ja/v2/Git-%E3%81%AE%E3%82%AB%E3%82%B9%E3%82%BF%E3%83%9E%E3%82%A4%E3%82%BA-Git-%E3%81%AE%E8%A8%AD%E5%AE%9A#_core_excludesfile)) でも GitHub Docs ([ファイルを無視する - GitHub Docs](https://docs.github.com/ja/free-pro-team@latest/github/using-git/ignoring-files)) でも `core.excludesfile` を用いていますが、これは「`$XDG_CONFIG_HOME` の差を避けるために意図的に選んで紹介している」のだと思われます。


## パターンの書き方

公式のリファレンス (<https://git-scm.com/docs/gitignore#_pattern_format>) に書いてあることがすべてです。

-   空行は無視される
-   `#` から始まる行は無視される
-   特殊な意味を持つ記号は `\` で escape できる
-   行末の空白は無視される
-   行頭に `!` を書くとその行の内容は反転 (無視されていたものを無視しないようにする）する。ただし、すでに無視されているディレクトリは (もしそのディレクトリの中に `.gitignore` が置かれていたとしても) 処理されることはないので注意が必要である
-   `/` はディレクトリの区切りとして認識される (訳中: Windows であっても `\` でなく `/` を使う)
-   行末以外の場所に `/` を含む行は、`.gitignore` の置かれた場所からの相対パスとして扱われる。`foo/bar` は `/foo/bar` と同じ意味であることに注意しよう
-   パターンの指定には `*` や `?` や `[a-zA-Z]` のような [fnmatch(3)](https://linuxjm.osdn.jp/html/LDP_man-pages/man3/fnmatch.3.html) に由来する記法が使える
-   パターンの指定には `**` という記法が使える。これは `/` を 0 個以上含むようなパスにマッチする


## 余談: この記事はなぜ書かれたのか

個人 OSS 開発をしていると "Add .gitignore" とか "Update .gitignore" というプルリクエストが送られてくることがあります。
たいていはその送り主が独自に利用しているエディタや環境のための設定が含まれています。
それは「あまりコードが書けない人でも作れるようなプルリクエスト[^beginner]なので気軽に送られてきて」「なにもしていないのに巻き込まれる自転車置場の議論」であり「なにかエンドユーザの利益になるわけではない」ために、受け取るとなんとなくもやっとした気持ちになります[^reject]。

この記事は、そのような気持ちになったために、とりあえず `.gitignore` について調べ直した結果をまとめたものです。
`.gitignore` の機能自体がかなり小さなものであったので、実質的に man page の全体の翻訳となっています[^translate]。
特になにかを意見を主張するための記事ではありません。

当初は、`.gitignore` に批判的な立場から「たとえば `node_modules/` のような言語依存だが実質的に常に無視されるべきファイルについても `$XDG_CONFIG_HOME/git/ignore` に書くべきだ。そのようなファイルは (JavaScript 以外の) すべてのリポジトリで無視して問題ないものであり、また無視されるべきである。そのような、すべてのリポジトリで無視されるべきものを `.gitignore` に書くべきではない。」を主張しようとしていました。しかし「このような思想の人は少なそう」「この方針では `.gitignore` についてのプルリクが来ることは避けられず、毎回説明が発生して面倒である」「多数派に逆らってまでこの方針での運用にこだわるほどの利益はまったくない」ために主張は取り下げられました。

現在は「`.gitignore` には、リポジトリで使われているワークフローや言語に依存するファイル (例: `node_modules/`) を書く。個人のエディタや IDE や環境に依存するファイル (例: `*.swp` `.vscode` `.DS_Store`) は書かない。」という (常識的な) 方針が面倒や不和を減らす意味で適切だろうと考えています。


## 参考

-   [Git - gitignore Documentation](https://git-scm.com/docs/gitignore)
    -   man page です。この記事の内容のほとんどすべてはここに書かれています。
-   [Git - 変更内容のリポジトリへの記録](https://git-scm.com/book/ja/v2/Git-%E3%81%AE%E5%9F%BA%E6%9C%AC-%E5%A4%89%E6%9B%B4%E5%86%85%E5%AE%B9%E3%81%AE%E3%83%AA%E3%83%9D%E3%82%B8%E3%83%88%E3%83%AA%E3%81%B8%E3%81%AE%E8%A8%98%E9%8C%B2)
-   [Git - Git の設定](https://git-scm.com/book/ja/v2/Git-%E3%81%AE%E3%82%AB%E3%82%B9%E3%82%BF%E3%83%9E%E3%82%A4%E3%82%BA-Git-%E3%81%AE%E8%A8%AD%E5%AE%9A)


## 脚注

[^beginner]: そのようなプルリクエストそのものが悪いわけではありません。誰しもそのようなレベルから初めるものであり、また、技術的に簡単であるかどうかとユーザにとって価値があるかは無関係です。
[^reject]: 特に、個人の環境にのみ依存したそのリポジトリに無関係なファイルについての指定を `.gitignore` に含めてしまうと、それとは別の個人の環境に依存した別のファイルについての指定を追加しろという別のプルリクエストを呼び込んでしまうだろうという問題があり、たいてい reject の方向で対応しています。
[^sejuku]: ちなみに他にもいろいろ変です。たとえば「gitignoreは……ファイル名で、このファイルに……」であり、「ファイル名」と「ファイル」の区別すら曖昧です。
[^suggest]: 少なくとも現時点の私の環境では
[^version]: `core.excludesfile` はより古くからある機能ですが、そのデフォルト値は 2012年8月に公開された Git v1.7.12 で追加されました (<https://lwn.net/Articles/512976/>, [git/Documentation/RelNotes/1.7.12.txt](https://github.com/git/git/blob/53f9a3e157dbbc901a02ac2c73346d375e24978c/Documentation/RelNotes/1.7.12.txt#L21-L23))
[^translate]: この記事を書くよりも、この man page を翻訳してプルリクエストを投げる方が適切だった可能性はあります。
