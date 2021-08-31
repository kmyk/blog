---
category: blog
layout: post
---

# Haskell 製の自作のトランスパイラを Asterius で WebAssembly にコンパイルしてみた

## TL;DR

-   ちゃんと動く
-   Alex と Happy は動かなかったので自前で展開した
-   Template Haskell は動いたが遅いので自前で展開した

## はじめに

Haskell の WebAssembly 環境はあまり充実しているとは言えません。
GHC 本体はまだ WebAssembly 対応はしてくれておらず、決定版となるツールは出てきていません。
2021 年夏現在の時点では、[tweag/asterius](https://github.com/tweag/asterius) が最も完成度が高そう、[ghcjs/ghcjs](https://github.com/ghcjs/ghcjs) は活発に開発が進められている、[WebGHC/wasm-cross](https://github.com/WebGHC/wasm-cross) は最近は動きがない、という状況です[^situation1][^situation2]。

さて今回は Asterius を試してみました。
Docker イメージが配布されていて最も動かしやすかったためです。
2 年前の時点では「コンパイルはできるが正しく動かない」「Template Haskell は使えない」という状況だったようですが[^igrep]、現在は「コンパイル結果はきちんと動く」「Template Haskell もすこし遅いがちゃんと使える」という結果でした。

成果物である Web ページは <https://kmyk.github.io/Jikka/playground/> にあります。

## 最低限の動かし方

Docker のイメージがあるのでまずその中に入り、`$ ahc-cabal new-install --installdir .` とやると pseudo-executable file がカレントディレクトリにできます。
これを `ahc-dist` に渡すと `.html` とか `.mjs` とかを作ってくれます。

``` console
kimiyuki@hostname/project$ docker run -it --rm -v $(pwd):/workspace -w /workspace terrorjack/asterius
root@hostname:/workspace# ahc-cabal new-update
root@hostname:/workspace# ahc-cabal new-install --installdir .
root@hostname:/workspace# ahc-dist --input-exe PSEUDO_EXECUTABLE_FILE --browser
```

## 実際に Web ページを作る

WebAssembly を使うとなるとどこまでを Haskell で実装してどこからを JavaScript で実装するかを考えることになります。
しかし未だ安定していない Haskell の WebAssembly 状況を考えれば、Asterius やその他のツールへの強依存は避けてできる限りを JavaScript で実装するのがよいでしょう。

まず Haskell 側から JavaScript 側へと export する関数を用意します。
以下のような `foreign export` 宣言をしたソースコードを用意し、これを `--ghc-options` に `-optl--export-function=func` を渡してビルドします。
コード例: ([asterius.hs](https://github.com/kmyk/Jikka/blob/master/app/asterius.hs))

``` haskell
import Asterius.Types

func' :: String -> String
func' = ...

func :: JSString -> JSString
func = toJSString . func' . fromJSString

foreign export javascript "func" func :: JSString -> JSString
```

JavaScript 側からこれを呼ぶには以下のようなボイラープレートを書きます。
Asterius が吐いた `rts.mjs`, `xxx.wasm.mjs`, `xxx.req.mjs` を読み込み、これらを組み合わせて `i.exports.func` を得ればよいです。
コード例: ([input.mjs](https://github.com/kmyk/Jikka/blob/master/docs/gh-pages/playground/input.mjs))

``` javascript
import * as rts from "./rts.mjs";
import wasm from "./xxx.wasm.mjs";
import req from "./xxx.req.mjs";

async function func(prog) {
  const m = await wasm;
  const i = await rts.newAsteriusInstance(Object.assign(req, { module: m }));
  return await i.exports.func(prog);
}

window.addEventListener("DOMContentLoaded", function () {
    ...
}
```

さらに上記の JavaScript を呼び出す HTML を書いて完成です。
お疲れ様でした。

## 問題とその対策: Alex と Happy が動かない

字句解析器に [Alex](https://www.haskell.org/alex/) を、構文解析器に [Happy](https://www.haskell.org/happy/) を用いていましたが、これらがどちらも `ahc-cabal` 経由では動作しませんでした。
`build-tools` に書く種類のツールはこれら以外でも動かないかもしれません。

この問題はコンテナの外側で手動でツールを実行してしまえば解決します。

``` console
$ find src -name \*.x | xargs -n1 alex
$ find src -name \*.x -delete
$ find src -name \*.y | xargs -n1 happy
$ find src -name \*.y -delete
```

## 問題とその対策: Template Haskell が遅い

Template Haskell は動作しますがすこし遅いです。
それなりの数の準クォートを使っていたのが原因でしょう。
GitHub Actions 上でのビルドだとちょうど 1 時間かかるという結果になってしまいました。
もともと 100 を越えるモジュールがあって普通に GHC でビルドするだけでも遅いので、まあしかたがないかなと思います。

対策は Alex と Happy の場合と同様にすればよいでしょう。
つまり `ghc` に `-ddump-splices` と `-ddump-to-file` を付けてまず普通にビルドをし、その結果を加工してソースコードを書き換えて Template Haskell を消去し、その結果の Template Haskell のないコードを Asterius でコンパイルすればよいです。
実際に利用したコードは [erase_template_haskell.py](https://github.com/kmyk/Jikka/blob/c1cf79c40ccdb576ec087b433f03c3cacdee51e4/scripts/erase_template_haskell.py) になります。

## 問題とその対策: 普通の GHC と共存できない

通常の `.cabal` に Asterius 用のルールを書いてしまうと、普通の GHC で `$ cabal build` とやったときにコンパイルエラーが出るようになってしまいます。
`.cabal` をふたつ用意して置き換えましょう。
本来は `if flag(..)` を使うべきでしょうが、`ahc-cabal` が混乱してしまうようでだめでした。

## 注釈

[^situation1]: [Is asterius the only viable haskell to webassembly compiler?](https://www.reddit.com/r/haskell/comments/bssqgp/is_asterius_the_only_viable_haskell_to/)
[^situation2]: [Ask: What is the state of Haskell targeting WebAssembly? : haskell](https://www.reddit.com/r/haskell/comments/foeyim/ask_what_is_the_state_of_haskell_targeting/)
[^igrep]: [AsteriusでHaskellの関数をJSから呼べるようにしてみた（けど失敗）（拡大版）](https://haskell.jp/blog/posts/2019/asterius.html)
