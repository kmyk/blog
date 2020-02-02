---
category: blog
layout: post
title: "競技プログラミングにおける実行時間の見積りについて"
date: "2019-05-17T00:00:00+09:00"
tags: [ "competitive", "atcoder" ]
---

## 周波数とクロックサイクルからの計算方法

実行する CPU における、その周波数 $f$ (クロックサイクル毎秒) と操作全体に必要なクロックサイクル数 $k$ に対し、(理論的な) 計算時間は $k/f$ 秒である。

例えば次のような事実が分かっているとする。

1.  CPU は $2.8$ GHz の物理コア $1$ 個を使えるとする。
1.  操作回数は $10^8$ 回である。
1.  $1$ 回の操作に $10$ クロックサイクル程度かかるとする。

このとき、計算時間は $10 \mathrm{[クロックサイクル]} \times 10^8 / 2.8 \mathrm{[GHz]} \approx 0.358 \mathrm{[秒]}$ となる。

## クロックサイクルの算出方法

操作 $1$ 回あたりのクロックサイクル数が分からなければ、上記の計算はできない。
その算出は CPU に強く依存しとても複雑であるが、C++ で競技プログラミングをやる場合に限れば以下のような雰囲気で把握していれば十分だろう。

-   bit演算: とても速い、$0.5 \sim 1$ クロックサイクル
-   整数加算 / 整数減算: 速い、$1$ クロックサイクルぐらい
-   整数乗算: まあまあ、$3 \sim 6$ クロックサイクルとか
-   整数除算 / 整数剰余: とても遅い、32 bit か 64 bit かにもよるが $12 \sim 40$ クロックサイクルなど
-   メモリアクセス: 速い、$0 \sim 4$ クロックサイクル (キャッシュミスが起きない場合)
-   条件分岐: 速い、$1 \sim 2$ クロックサクイルぐらい (分岐予測が当たった場合)

ただしここに追加で以下のような要素が加わる。
定数倍最適化で無理矢理通すことをするなら考慮が必要となる。

-   キャッシュミス: CPU の近くにデータがないと遠くまで読み込みにいくことになって遅い。L3 キャッシュまで取りに行くと $44$ クロックサイクルぐらい、RAM まで取りに行くと最悪で $180$ クロックサイクルとか
-   分岐予測ミス: 他の重い計算をしてる間に条件分岐の結果を予測して投機的に実行してくれる CPU の機能があるが、この予測を外すと $10 \sim 20$ クロックサイクルぐらい損をする
-   SIMD: コンパイラが上手く式変形をして $128$ bitや $256$ bit分のデータをまとめて処理する命令が利用されると速い。例えば、$32$ bitの演算を $128$ bitに詰めてまとめて行なえば $4$倍速

細かい数値は [Infographics: Operation Costs in CPU Clock Cycles](http://ithare.com/infographics-operation-costs-in-cpu-clock-cycles/) から借りた。
詳細が気になる人は[パタ](https://www.amazon.co.jp/dp/4822298426)[ヘネ](https://www.amazon.co.jp/dp/4822298434)や[ヘネパタ](https://www.amazon.co.jp/dp/4798126233)、あるいは [Intel® 64 and IA-32 Architectures Software Developer Manuals](https://software.intel.com/en-us/articles/intel-sdm) などを自分で読むとよい。

なお、`std::map` や `std::unordered_map` のようなたくさんの CPU 命令の塊はもちろん遅いので注意しよう。
関数呼出も場合によっては遅いが、競プロの範囲内ならたいてい無視できるだろう。

## おまけ: AtCoderの環境情報

以下のようになった。
周波数は $2.8$ GHz で、SIMD系のフラグは `avx` まで立っているが `avx2` は立っていない。
SIMD がよく効く単純なループなら $1$ 秒間に $10^{10} \approx 2.8 \times 10^9 / 0.25$ 回の操作も狙えるが、中で毎回 MOD を取る場合は $1$ 秒間に $7 \times 10^7 \approx 2.8 \times 10^9 / 40$ 回の操作でも厳しいかもしれない、などが分かる。

``` console
$ date
Fri May 17 17:32:09 JST 2019

$ cat /proc/cpuinfo
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 62
model name	: Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
stepping	: 4
microcode	: 0x42d
cpu MHz		: 2793.316
cache size	: 25600 KB
physical id	: 0
siblings	: 2
core id		: 0
cpu cores	: 1
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology eagerfpu pni pclmulqdq ssse3 cx16 pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm xsaveopt fsgsbase smep erms
bogomips	: 5586.63
clflush size	: 64
cache_alignment	: 64
address sizes	: 46 bits physical, 48 bits virtual
power management:

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 62
model name	: Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
stepping	: 4
microcode	: 0x42d
cpu MHz		: 2793.316
cache size	: 25600 KB
physical id	: 0
siblings	: 2
core id		: 0
cpu cores	: 1
apicid		: 1
initial apicid	: 1
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology eagerfpu pni pclmulqdq ssse3 cx16 pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm xsaveopt fsgsbase smep erms
bogomips	: 5586.63
clflush size	: 64
cache_alignment	: 64
address sizes	: 46 bits physical, 48 bits virtual
power management:

```

---

-   2019年  5月 17日 金曜日 19:30:54 JST
    -   $f/k$ 秒になってたのを教えてもらったので修正 (<https://twitter.com/noshi91/status/1129329898043035649>)
    -   メモリアクセスの速度を、分かりやすさを優先したものから突っ込みの入りにくさを優先したものに修正
