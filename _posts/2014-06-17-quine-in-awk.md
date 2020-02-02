---
category: blog
layout: post
title: "awkでquine書いた"
date: 2014-06-17T20:51:00+09:00
tags: [ "awk", "quine" ]
---

``` awk
#!/usr/bin/awk -f
BEGIN {
    s="#!/usr/bin/awk -f\nBEGIN {\n    s=%s;\n    t=s;\n    gsub(\"\\\\\\\\\", \"\\\\\\\\\", t);\n    gsub(\"\\\"\", \"\\\\\\\"\", t);\n    gsub(\"\\n\", \"\\\\n\", t);\n    t=\"\\\"\" t \"\\\"\";\n    printf(s,t);\n}\n";
    t=s;
    gsub("\\\\", "\\\\", t);
    gsub("\"", "\\\"", t);
    gsub("\n", "\\n", t);
    t="\"" t "\"";
    printf(s,t);
}
```

-   quineは書くこと/書けることが無い時の暇潰しに良いと気付きました
-   `gsub`がキャプチャできないの知りませんでした
