---
category: blog
layout: post
redirect_from:
    - "/blog/2015/09/18/how-to-make-packages-of-arch-linux/"
date: 2015-09-19T01:23:14+09:00
tags: [ "arch" ]
---

# Arch Linuxでの野良packageの作成方法

詳しい方法は全部ArchWikiに日本語で載っているが、要点だけまとめておけば私が楽だから書く。
checkinstallの代わりにpacmanを使うといったことを想定しており、他人に配布するためのものを作るのであればArchWikiを読むこと。

<!-- more -->

## PKGBUILD

まず`PKGBUILD`を作成する。
これはバイナリパッケージを作るための、Makefileのようなものである。

bashとして実行されるshellscriptで、いくつかの変数と関数を定義する必要がある。
最小構成は以下。

``` sh
pkgname=NAME
pkgver=VERSION
pkgrel=1
arch=('any')
package() {
    ...
}
```

書き始めには[`/usr/share/pacman/PKGBUILD.proto`](file:///usr/share/pacman/PKGBUILD.proto)を元にするとよい。

### 変数

`$pkgname`, `$pkgver`は生成されるpackageのそれになる。`$pkgrl`, `$arch`は無視してよい。

他の変数として`$source`(配列)がある。compileに必要なfileを列挙する。urlでもよい。圧縮fileは自動で展開してくれる。
大抵の場合以下のようになるだろう。

例:

``` sh
source=("$pkgname-$pkgver.tar.gz")
```

`$source`を加えた場合`$updpkgsums`がないと`ERROR: Integrity checks are missing.`など言われることがある。この場合、

``` sh
$ updpkgsums
```

と叩けば、`PKGBUILD`に破壊的に追記してくれる。

### 関数

`package()`内部にはinstallのための処理を書く。
`/`の代わりに`$pkgdir`以下にファイルを配置する。
`$pkgdir/usr/bin/foo`というファイルを作成するよう書けば、packageの作成の際に回収され、`/usr/bin/foo`

以下はその例である。

``` sh
package() {
    cd "$pkgname-$pkgver"
    ./configure --prefix="$pkgdir/usr"
    make
    make install
}
```

`$pkgdir`内のファイルに`$pkgdir`の表す文字列が残っていると、おそらく問題が発生する。
`makepkg`の段階で`WARNING: Package contains reference to $pkgdir`などと報告があるので、そのときは対応すべきである。

## \*.pkg.tar.xz

最後に、`makepkg`で`PKGBUILD`に従いバイナリパッケージを作成する。
できたそれをpacmanに渡すとsystem環境への展開がなされる。

``` sh
$ makepkg
$ sudo pacman -U $pkgname-$pkgver-$pkgrel-$arch.pkg.tar.xz
```

## 参考

-   [パッケージの作成 - ArchWiki](https://wiki.archlinuxjp.org/index.php/%E3%83%91%E3%83%83%E3%82%B1%E3%83%BC%E3%82%B8%E3%81%AE%E4%BD%9C%E6%88%90)
-   [makepkg - ArchWiki](https://wiki.archlinuxjp.org/index.php/Makepkg)
-   [Arch Build System - ArchWiki](https://wiki.archlinuxjp.org/index.php/Arch_Build_System)
-   [PKGBUILD - ArchWiki](https://wiki.archlinuxjp.org/index.php/PKGBUILD)
