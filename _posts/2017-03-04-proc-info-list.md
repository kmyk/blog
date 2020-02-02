---
category: blog
layout: post
date: "2017-03-04T01:06:27+09:00"
title: "オンラインジャッジサーバの/proc/cpuinfoを集めた"
tags: [ "competitive", "simd" ]
---

-   Codeforcesではthread並列がよく効く
    -   それ以外では基本的にだめ
-   SIMDはAVXまでならどこでも使える
-   2017年3月3日時点

## AtCoder

Custom Test機能

AWS c3.largeらしい

```
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model           : 62
model name      : Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
stepping        : 4
microcode       : 0x428
cpu MHz         : 2793.322
cache size      : 25600 KB
physical id     : 0
siblings        : 2
core id         : 0
cpu cores       : 1
apicid          : 0
initial apicid  : 0
fpu             : yes
fpu_exception   : yes
cpuid level     : 13
wp              : yes
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology eagerfpu pni pclmulqdq ssse3 cx16 pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm xsaveopt fsgsbase smep erms
bogomips        : 5586.64
clflush size    : 64
cache_alignment : 64
address sizes   : 46 bits physical, 48 bits virtual
power management:

processor       : 1
vendor_id       : GenuineIntel
cpu family      : 6
model           : 62
model name      : Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
stepping        : 4
microcode       : 0x428
cpu MHz         : 2793.322
cache size      : 25600 KB
physical id     : 0
siblings        : 2
core id         : 0
cpu cores       : 1
apicid          : 1
initial apicid  : 1
fpu             : yes
fpu_exception   : yes
cpuid level     : 13
wp              : yes
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology eagerfpu pni pclmulqdq ssse3 cx16 pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm xsaveopt fsgsbase smep erms
bogomips        : 5586.64
clflush size    : 64
cache_alignment : 64
address sizes   : 46 bits physical, 48 bits virtual
power management:
```

## YukiCoder

writer権限による標準出力の表示による。<http://yukicoder.me/help/environments>とは食い違っていた(おそらくコピペミス)。

実際に速度を見ると物理$1$コアに見える。
Dockerの機能で物理$1$コア指定されているのではという指摘があり、おそらくこれだろう: <https://twitter.com/fmhr__/status/864927138176057345>

```
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 62
model name	: Intel(R) Xeon(R) CPU E5-2650 v2 @ 2.60GHz
stepping	: 4
microcode	: 0x1
cpu MHz		: 2599.998
cache size	: 20480 KB
physical id	: 0
siblings	: 1
core id		: 0
cpu cores	: 1
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl eagerfpu pni pclmulqdq vmx ssse3 cx16 pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm vnmi ept fsgsbase tsc_adjust smep erms xsaveopt
bogomips	: 5199.99
clflush size	: 64
cache_alignment	: 64
address sizes	: 40 bits physical, 48 bits virtual
power management:

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 62
model name	: Intel(R) Xeon(R) CPU E5-2650 v2 @ 2.60GHz
stepping	: 4
microcode	: 0x1
cpu MHz		: 2599.998
cache size	: 20480 KB
physical id	: 1
siblings	: 1
core id		: 0
cpu cores	: 1
apicid		: 1
initial apicid	: 1
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl eagerfpu pni pclmulqdq vmx ssse3 cx16 pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm vnmi ept fsgsbase tsc_adjust smep erms xsaveopt
bogomips	: 5199.99
clflush size	: 64
cache_alignment	: 64
address sizes	: 40 bits physical, 48 bits virtual
power management:

processor	: 2
vendor_id	: GenuineIntel
cpu family	: 6
model		: 62
model name	: Intel(R) Xeon(R) CPU E5-2650 v2 @ 2.60GHz
stepping	: 4
microcode	: 0x1
cpu MHz		: 2599.998
cache size	: 20480 KB
physical id	: 2
siblings	: 1
core id		: 0
cpu cores	: 1
apicid		: 2
initial apicid	: 2
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl eagerfpu pni pclmulqdq vmx ssse3 cx16 pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm vnmi ept fsgsbase tsc_adjust smep erms xsaveopt
bogomips	: 5199.99
clflush size	: 64
cache_alignment	: 64
address sizes	: 40 bits physical, 48 bits virtual
power management:

processor	: 3
vendor_id	: GenuineIntel
cpu family	: 6
model		: 62
model name	: Intel(R) Xeon(R) CPU E5-2650 v2 @ 2.60GHz
stepping	: 4
microcode	: 0x1
cpu MHz		: 2599.998
cache size	: 20480 KB
physical id	: 3
siblings	: 1
core id		: 0
cpu cores	: 1
apicid		: 3
initial apicid	: 3
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl eagerfpu pni pclmulqdq vmx ssse3 cx16 pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm vnmi ept fsgsbase tsc_adjust smep erms xsaveopt
bogomips	: 5199.99
clflush size	: 64
cache_alignment	: 64
address sizes	: 40 bits physical, 48 bits virtual
power management:
```

## HackerRank

Run Code機能

AWS c3.largeっぽい

```
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model           : 62
model name      : Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
stepping        : 4
microcode       : 0x428
cpu MHz         : 2793.338
cache size      : 25600 KB
physical id     : 0
siblings        : 2
core id         : 0
cpu cores       : 1
apicid          : 0
initial apicid  : 0
fpu             : yes
fpu_exception   : yes
cpuid level     : 13
wp              : yes
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology eagerfpu pni pclmulqdq ssse3 cx16 pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm xsaveopt fsgsbase smep erms
bogomips        : 5586.67
clflush size    : 64
cache_alignment : 64
address sizes   : 46 bits physical, 48 bits virtual
power management:

processor       : 1
vendor_id       : GenuineIntel
cpu family      : 6
model           : 62
model name      : Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
stepping        : 4
microcode       : 0x428
cpu MHz         : 2793.338
cache size      : 25600 KB
physical id     : 0
siblings        : 2
core id         : 0
cpu cores       : 1
apicid          : 1
initial apicid  : 1
fpu             : yes
fpu_exception   : yes
cpuid level     : 13
wp              : yes
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology eagerfpu pni pclmulqdq ssse3 cx16 pcid sse4_1 sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm xsaveopt fsgsbase smep erms
bogomips        : 5586.67
clflush size    : 64
cache_alignment : 64
address sizes   : 46 bits physical, 48 bits virtual
power management:
```

## Anarchy Golf

Performance checker

```
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model           : 15
model name      : Intel(R) Core(TM)2 Duo CPU     T7700  @ 2.40GHz
stepping        : 11
cpu MHz         : 2659.842
cache size      : 4096 KB
fdiv_bug        : no
hlt_bug         : no
f00f_bug        : no
coma_bug        : no
fpu             : yes
fpu_exception   : yes
cpuid level     : 10
wp              : yes
flags           : fpu de tsc msr pae cx8 cmov pat clflush mmx fxsr sse sse2 nx constant_tsc up pni ssse3 hypervisor
bogomips        : 5319.68
clflush size    : 64
cache_alignment : 64
address sizes   : 40 bits physical, 48 bits virtual
power management:
```

## Codeforces

-   Windowsなので`/proc/cpuinfo`はないが、それっぽく整理した
-   CUSTOM INVOCATION機能
-   <https://github.com/pydata/numexpr/blob/master/numexpr/cpuinfo.py>
-   <https://msdn.microsoft.com/en-us/library/hskdteyh.aspx>/InstructionSet.cpp
-   使用感:
    -   `std::thread`がそのまま使えた
    -   きれいに並列化が効けば$2$倍速ぐらいになる
    -   物理コアはひとつだけっぽい？

```
processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model           : 58
model name      : Intel(R) Core(TM) i5-3470 CPU @ 3.20GHz
stepping        : 9
cpu MHz         : 3200
flags*          : AES AVX CLFSH CMPXCHG16B CX8 ERMS F16C FSGSBASE FXSR LAHF MMX MONITOR MSR OSXSAVE PCLMULQDQ POPCNT RDRAND RDTSCP SEP SSE SSE2 SSE3 SSE4.1 SSE4.2 SSSE3 XSAVE

processor       : 1
vendor_id       : GenuineIntel
cpu family      : 6
model           : 58
model name      : Intel(R) Core(TM) i5-3470 CPU @ 3.20GHz
stepping        : 9
cpu MHz         : 3200
flags*          : AES AVX CLFSH CMPXCHG16B CX8 ERMS F16C FSGSBASE FXSR LAHF MMX MONITOR MSR OSXSAVE PCLMULQDQ POPCNT RDRAND RDTSCP SEP SSE SSE2 SSE3 SSE4.1 SSE4.2 SSSE3 XSAVE

processor       : 2
vendor_id       : GenuineIntel
cpu family      : 6
model           : 58
model name      : Intel(R) Core(TM) i5-3470 CPU @ 3.20GHz
stepping        : 9
cpu MHz         : 3200
flags*          : AES AVX CLFSH CMPXCHG16B CX8 ERMS F16C FSGSBASE FXSR LAHF MMX MONITOR MSR OSXSAVE PCLMULQDQ POPCNT RDRAND RDTSCP SEP SSE SSE2 SSE3 SSE4.1 SSE4.2 SSSE3 XSAVE

processor       : 3
vendor_id       : GenuineIntel
cpu family      : 6
model           : 58
model name      : Intel(R) Core(TM) i5-3470 CPU @ 3.20GHz
stepping        : 9
cpu MHz         : 3200
flags*          : AES AVX CLFSH CMPXCHG16B CX8 ERMS F16C FSGSBASE FXSR LAHF MMX MONITOR MSR OSXSAVE PCLMULQDQ POPCNT RDRAND RDTSCP SEP SSE SSE2 SSE3 SSE4.1 SSE4.2 SSSE3 XSAVE
```

## Aizu Online Judge

-   <http://judge.u-aizu.ac.jp/onlinejudge/system_info.jsp>
-   <https://ark.intel.com/products/80913/Intel-Xeon-Processor-E3-1286-v3-8M-Cache-3_70-GHz>

```
model name      : Intel(R) Xeon(R) Processor E3-1286 v3 3.7 GHz, Turbo 4C/8T
flags*          : SSE4.1/4.2, AVX 2.0 ...
```

---

-   2017年  3月  8日 水曜日 00:27:07 JST
    -   Codeforcesで実際に使ってみたので追記
-   2017年  5月 18日 木曜日 02:33:17 JST
    -   すこし追記
-   2017年  5月 18日 木曜日 03:54:18 JST
    -   Yukicoderについて修正
