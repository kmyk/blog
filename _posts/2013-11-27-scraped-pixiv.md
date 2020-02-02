---
category: blog
layout: post
title: "pixivをscarpingした"
date: 2013-11-27T21:47:44+09:00
tags: [ "javascript", "scarping", "pixiv" ]
---

## [pixiv-tools](https://github.com/kmyk/pixiv-tools)
勢いで作った  
CasperJS + PhantomJS でかなり強引に処理

<!-- more -->

## memo

### javascript (や flash)を扱えるlibraryたち
- mechanizeさんはむりぽ
- 他にもたくさん

#### [PhantomJS](http://phantomjs.org/)
- WebKit
- nodeでない
- [CasperJS](http://casperjs.org/)
    - nodejsでないwrapper
- [Node.js](http://nodejs.org/)
    - bridge はいくつかあったが、結局使わなかった
       - [phantomjs-node](https://github.com/sgentle/phantomjs-node)
       - [SpookyJS](https://github.com/WaterfallEngineering/SpookyJS)
       - [phantomjs](https://github.com/Obvious/phantomjs)

#### [Chimera](https://github.com/deanmao/node-chimera)
- WebKit
- `npm install chimera`
- うまく使えなかった
- documentどこですか

#### [SlimerJS](http://slimerjs.org/)
- Gecko
- 試してないのでよく分からない

### 競合

#### [PixivUtil2](https://github.com/Nandaka/PixivUtil2)
- 作り終わってから見つけた 少し触った
- python + mechanize 製
- script tag内をそれらしいurlでgrepしてる
- 機能豊富で良くできている むしろ多すぎ感ある
