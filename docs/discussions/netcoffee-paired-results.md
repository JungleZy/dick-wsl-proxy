# Net.Coffee 双发行版公网诊断

实验：`netcoffee-gtzqRW`；仅使用 D 盘两个实验发行版。原始证据：`D:\WSL\ProxyLab\netcoffee-gtzqRW\`。报告中的业务出口以 Target / Control 表示，完整地址保存在实验机。

## 一、透明 IPv4 与 Net.Coffee 首页

两个发行版的 eth0 均为 `172.28.83.138/20`，默认解析器均为 `10.255.255.254`。固定同一目的 IPv4 `104.21.53.138`、HTTPS 443，保留主机名和证书校验；两组不向 curl 设置应用代理。仅 Target 通过临时规则进入 Windows、TrojanX 本地入口和已认证住宅 SOCKS5。Control 在规则启用期间仍按原路径联网。此处固定地址排除 DNS 差异，DNS 另测。

| 测项 | Target | Control |
|---|---|---|
| 对端看到的 IPv4（脱敏） | 154.64.151.* | 106.85.173.* |
| 国家 / Cloudflare 节点 / 协议 | US / PDX / TLSv1.3 / http/1.1 / off | CN / AMS / TLSv1.3 / http/1.1 / off |
| 首页 HTTP 状态 / 响应字节 | 200 / 16078 | 200 / 16078 |
| 3 次新连接，首字节 ms | 3293, 3716, 4464 | 1792, 1655, 823 |
| 3 次新连接，总耗时 ms | 3707, 3831, 4481 | 1807, 1667, 833 |
| 总耗时中位数 ms | 3831 | 1667 |

Target 四个 HTTPS 请求各命中一次规则，Control 四个请求合计命中零次，全部 HTTP 200，TLS 校验通过。`colo` 是 CDN 接入节点，不是客户端所在地。

## 二、主页 IPv4 来源和分流出口：全部 43 项

以下批量探测从对应发行版执行：Target 显式连接同一 Windows 住宅链路，Control 禁用应用代理。它验证该链访问各目标的效果，不表示每个多站点请求都经过临时内核规则。每组包括 37 个 CF trace、网易/字节 2 个响应头探测、主页 IPv4 源 3 个、独立 CF 参照 1 个。只把实际返回的客户端 IP 计为出口证据。无回显不推断成直连。

| 探测名 / 域名 | Target | Control |
|---|---|---|
| www.cloudflare-cn.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| www.qualcomm.cn | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| gateway.discord.gg | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| x.com | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| medium.com | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| quora.com | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| signal.org | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| anthropic.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| claude.ai | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| chatgpt.com | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| openai.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| sora.com | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| grok.com | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| pixpix.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| www.perplexity.ai | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 35 |
| midjourney.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| mistral.ai | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| coinbase.com | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| www.okx.com | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| www.binance.info | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 35 |
| crypto.com | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| st1.zoom.us | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| deepl.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| wise.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| poe.com | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| notion.so | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| shopify.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| godaddy.com | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 7 |
| producthunt.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| www.cloudflare.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| cdnjs.cloudflare.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| registry.npmjs.org | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| kali.download | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| unpkg.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| nodejs.org | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| gitlab.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| crunchyroll.com | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| cloudflare-ipv4-reference | 本组出口 · HTTP 200 | 无回显 · HTTP — · curl 28 |
| ip138 | 无回显 · HTTP 403 · curl 0 | 无回显 · HTTP 302 · curl 7 |
| ipcn | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| ipip | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| netease | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |
| bytedance | 本组出口 · HTTP 200 | 本组出口 · HTTP 200 |

curl 28 为超时，35 为 TLS 握手失败，7 为连接失败；收到 HTTP 403 等响应不等于网络不通。IP138 如有跳转失败，HTTP 一栏可能是上一跳状态。

## 三、DNS：系统默认、远程解析、受控系统 DNS 分开测量

使用 [Net.Coffee 权威 DNS](https://ip.net.coffee/dns/) 的新 token，每轮 5 个不同名称，通过其结果 API 取权威端实际观察到的递归出口。Target 应用远程解析由住宅端处理域名；受控系统 DNS 则是在 Target 子树内仅为测试身份临时引流到 Windows，再经住宅链使用 Google DoH。Control 不改动。递归出口与网页出口是不同实体，不要求 IP 相同。

| 测试 / UTC | 探测方法 | 权威端观察到的递归 IPv4（完整） |
|---|---|---|
| Control-active-original · 2026-11-19T03:07:09Z | 5/5 系统解析成功 | 221.231.139.97, 221.231.139.96 |
| Control-during-protected-original · 2026-11-19T03:10:29Z | 5/5 系统解析成功 | 221.231.139.97, 221.231.139.96 |
| Control-original · 2026-11-19T03:05:24Z | 5/5 系统解析成功 | 221.231.139.96, 221.231.139.97 |
| Target-original · 2026-11-19T03:06:52Z | 5/5 系统解析成功 | 221.231.139.96, 221.231.139.97 |
| Target-remote · 2026-11-19T03:05:54Z | 5 个新名称，域名在住宅端解析；不以像素 HTTP 成功计数 | 104.23.161.89, 172.68.173.166, 104.23.161.88 |
| Target-transparent · 2026-11-19T03:08:23Z | 5/5 系统解析成功 | 172.253.244.150, 74.125.186.155, 172.253.0.16, 172.253.192.145, 172.253.0.18, 74.125.17.187, 172.217.37.208, 172.253.244.144, 172.253.244.152, 172.253.86.84 |
| Target-transparent · 2026-11-19T03:10:29Z | 5/5 系统解析成功 | 172.253.244.144, 172.253.2.24, 172.253.2.30, 172.253.9.222, 172.253.9.216, 172.253.9.213, 172.253.2.17, 172.253.2.29, 172.253.2.23, 172.253.9.215, 172.253.2.28 |

两组未接管 DNS 时均观察到中国电信 `221.231.139.96/.97`；即使网页已从美国出站，系统 DNS 仍可保留本地路径。住宅端远程解析出现 Cloudflare 波特兰节点；显式选择 Google DoH 的受控系统 DNS 出现另一组公网递归地址。两轮受控系统 DNS 没有在权威端看到基线电信地址；同期 Control 仍为电信。不能从此推出所有应用、IPv6、DoH/DoT 均无泄漏。DNS API 没有返回 ASN，未用服务商名字推算。个别地址地理补全超时不影响权威端记录。

原始系统查询的成功样本中位用时：Target 252 ms、Control 201 ms。受控系统 DNS 两轮分别为 993 ms 和 1,077 ms；同步对照为 Control 979 ms。六组系统解析共 30/30 次成功，实际发出的为 UDP 查询；不能据此声称也测了 TCP 53。另一次住宅端远程解析由权威端记录到 3 个递归器；像素下载有 4 次本地二进制解析错误、1 次超时，不计为 HTTPS 成功。临时 DNS 和网页规则、测试监听均已移除，`resolv.conf` 未改动；见 `dns/conclusions.json`、`final-cleanup.txt`。

## 四、主页六项延迟

每组每端点 3 次独立 HTTPS 冷请求，最多 15 秒；下表为完成请求的总耗时中位数 [最小–最大]，单位毫秒。不是 ICMP，也不是原网页的浏览器连接复用与 2.5 秒超时评分。HTTP 404 是收到响应，不是应用成功。淘宝首次测试的跳转被实验白名单挡住，已用允许原站与跳转目标的受限入口重做；表中取校正值。

| URL | Target 中位数 [范围]；完成数 | Control 中位数 [范围]；完成数 |
|---|---|---|
| https://perfops.byte-test.com/500b-bench.jpg | 4420 [3199–4536]；3/3 | 141 [129–181]；3/3 |
| https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico | 4088 [2707–6737]；3/3 | 95 [84–140]；3/3 |
| https://github.com/generate_204 | 3222 [2382–3549]；3/3 | 337 [337–337]；1/3 |
| https://1.1.1.1/cdn-cgi/trace | 2053 [1663–6957]；3/3 | 无；0/3 |
| https://www.youtube.com/generate_204 | 2098 [1996–3577]；3/3 | 无；0/3 |
| https://www.taobao.com/favicon.ico | 11646 [8225–11666]；3/3 | 116 [111–149]；3/3 |

## 五、区域连通性页：全部 60 个端点

采用 [Net.Coffee `/link/`](https://ip.net.coffee/link/) 公布的探测 URL，各端点先预热 1 次，再同一 curl 进程连续 GET 8 次，可复用连接。单次期限 2.5 秒，使用较小并发（每组 6 个端点），表中取收到 HTTP 响应的首字节延迟的上中位数，单位毫秒；括号为有效样本数/8。统计首个 HTTPS 响应，不跟随跳转，HTTP 错误响应也算可达；不是检测站点功能或逐帧复现浏览器。超时不计入中位数；— 表示本轮没有有效样本。两组可能选择不同 CDN 节点。

| 网站分区 | 站点 | Target ms（成功/8） | Control ms（成功/8） |
|---|---|---:|---:|
| CN | [DeepSeek](https://www.deepseek.com/favicon.ico) | 305 (8/8) | 44 (8/8) |
| CN | [抖音](https://lf3-static.bytednsdoc.com/obj/eden-cn/favicon.ico) | 299 (6/8) | 37 (8/8) |
| CN | [哔哩哔哩](https://www.bilibili.com/favicon.ico) | — (0/8) | 19 (8/8) |
| CN | [京东](https://www.jd.com/favicon.ico) | — (0/8) | 9 (8/8) |
| CN | [腾讯QQ](https://mat1.gtimg.com/qqcdn/xw/favicon.ico) | 272 (8/8) | 14 (8/8) |
| CN | [微信](https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico) | 324 (8/8) | 8 (8/8) |
| CN | [飞书](https://lf-package-cn.feishucdn.com/obj/feishu-static/lark/open/website/favicon.png) | 285 (8/8) | 36 (8/8) |
| CN | [小红书](https://fe-static.xhscdn.com/favicon.ico) | 302 (7/8) | 35 (8/8) |
| CN | [百度](https://www.baidu.com/favicon.ico) | — (0/8) | 34 (8/8) |
| CN | [新浪微博](https://tva1.sinaimg.cn/favicon.ico) | — (0/8) | 13 (8/8) |
| CN | [淘宝](https://gw.alicdn.com/imgextra/i4/O1CN01qOI6vB1zaqrBKbyFr_!!6000000006731-73-tps-64-64.ico) | 351 (8/8) | 12 (8/8) |
| CN | [小米](https://www.mi.com/favicon.ico) | — (0/8) | 43 (8/8) |
| JP | [Sony](https://www.sony.jp/favicon.ico) | 485 (8/8) | 614 (8/8) |
| JP | [任天堂](https://www.nintendo.co.jp/favicon.ico) | — (0/8) | 340 (8/8) |
| JP | [Yahoo! JP](https://www.yahoo.co.jp/favicon.ico) | 2163 (1/8) | 135 (8/8) |
| JP | [LINE](https://line.me/favicon.ico) | 2170 (2/8) | — (0/8) |
| JP | [软银](https://www.softbank.jp/favicon.ico) | 333 (5/8) | 701 (8/8) |
| JP | [PixTV](https://www.pixtv.ai/favicon.ico) | 377 (6/8) | 86 (8/8) |
| JP | [Rakuten](https://www.rakuten.co.jp/favicon.ico) | — (0/8) | — (0/8) |
| JP | [Crunchyroll](https://crunchyroll.com/cdn-cgi/trace) | 259 (8/8) | 86 (8/8) |
| US | [Apple](https://www.apple.com/favicon.ico) | 518 (8/8) | 13 (8/8) |
| US | [Google](https://www.google.com/generate_204) | 510 (8/8) | — (0/8) |
| US | [YouTube](https://www.youtube.com/generate_204) | 332 (8/8) | — (0/8) |
| US | [GitHub](https://github.com/generate_204) | 627 (8/8) | 108 (7/8) |
| US | [ChatGPT](https://chatgpt.com/cdn-cgi/trace) | 266 (7/8) | — (0/8) |
| US | [Claude](https://api.anthropic.com/cdn-cgi/trace) | 611 (6/8) | 270 (8/8) |
| US | [AI Studio](https://generativelanguage.googleapis.com/generate_204) | 341 (7/8) | — (0/8) |
| US | [Grok](https://grok.com/cdn-cgi/trace) | 542 (7/8) | — (0/8) |
| US | [Instagram](https://static.cdninstagram.com/rsrc.php/yb/r/hLRJ1GG_y0J.ico) | 261 (8/8) | — (0/8) |
| US | [Facebook](https://static.xx.fbcdn.net/rsrc.php/yb/r/hLRJ1GG_y0J.ico) | 635 (8/8) | — (0/8) |
| US | [WhatsApp](https://static.whatsapp.net/rsrc.php/y1/r/FJbTMJqMap7.svg) | 303 (8/8) | — (0/8) |
| US | [Discord](https://discord.com/cdn-cgi/trace) | 261 (6/8) | — (0/8) |
| US | [X](https://abs.twimg.com/favicons/twitter.3.ico) | 283 (7/8) | — (0/8) |
| US | [Reddit](https://www.reddit.com/favicon.ico) | 526 (7/8) | — (0/8) |
| US | [Amazon](https://www.amazon.com/favicon.ico) | 416 (7/8) | 380 (7/8) |
| US | [PayPal](https://www.paypalobjects.com/favicon.ico) | 311 (8/8) | 76 (8/8) |
| US | [Cloudflare](https://1.1.1.1/cdn-cgi/trace) | 257 (7/8) | — (0/8) |
| US | [Bing](https://www.bing.com/favicon.ico) | 263 (8/8) | 37 (8/8) |
| US | [Steam](https://store.steampowered.com/favicon.ico) | 310 (8/8) | 685 (8/8) |
| US | [Xbox](https://www.xbox.com/favicon.ico) | 458 (8/8) | 387 (8/8) |
| US | [Netflix](https://assets.nflxext.com/us/ffe/siteui/common/icons/nficon2016.ico) | 264 (8/8) | 176 (8/8) |
| US | [Disney+](https://www.disneyplus.com/favicon.ico) | 344 (8/8) | 399 (8/8) |
| US | [Zoom](https://st1.zoom.us/favicon.ico) | 273 (8/8) | 271 (8/8) |
| US | [Twitch](https://static.twitchcdn.net/assets/favicon-32-e29e246c157142c94346.png) | 265 (8/8) | 182 (8/8) |
| GL | [TikTok](https://www.tiktok.com/favicon.ico) | 339 (8/8) | — (0/8) |
| GL | [Spotify](https://open.spotify.com/favicon.ico) | 274 (8/8) | — (0/8) |
| GL | [npm](https://registry.npmjs.org/) | 287 (8/8) | 214 (8/8) |
| GL | [jsDelivr](https://cdn.jsdelivr.net/favicon.ico) | 288 (8/8) | 232 (8/8) |
| GL | [PixPix](https://www.pixpix.com/favicon.ico) | 342 (5/8) | 105 (8/8) |
| GL | [DeepL](https://deepl.com/cdn-cgi/trace) | 282 (8/8) | 160 (8/8) |
| GL | [BBC](https://www.bbc.com/favicon.ico) | 305 (8/8) | — (0/8) |
| GL | [Noon](https://www.noon.com/favicon.ico) | — (0/8) | — (0/8) |
| GL | [Shopee](https://shopee.sg/favicon.ico) | — (0/8) | 87 (8/8) |
| GL | [Booking](https://cf.bstatic.com/favicon.ico) | 611 (8/8) | 326 (8/8) |
| GL | [Wikipedia](https://www.wikipedia.org/static/favicon/wikipedia.ico) | 326 (8/8) | — (0/8) |
| GL | [Naver](https://www.naver.com/favicon.ico) | 392 (4/8) | 75 (8/8) |
| GL | [Mistral AI](https://mistral.ai/cdn-cgi/trace) | 342 (6/8) | — (0/8) |
| GL | [Takealot](https://static.takealot.com/favicon.ico) | 342 (6/8) | 276 (8/8) |
| GL | [Yandex](https://yastatic.net/favicon.ico) | 353 (3/8) | 234 (8/8) |
| GL | [MercadoLibre](https://http2.mlstatic.com/ui/navigation/5.18.1/mercadolibre/favicon.ico) | 476 (5/8) | 409 (8/8) |

## 原始证据

- `main-Target.json`、`main-Control.json`、`main-Target.out`：透明首页三次冷请求、同站 trace、规则命中差值。
- `egress/report-full.txt`、`egress/results-full.json`：43 个出口诊断及首页 6 站全部原始与修正轮次，含失败时长和原因。
- `dns/summary.json`、各轮 DNS JSON：权威记录、API 返回的归属地、失败与重试、DNS 规则清理记录。
- `region/Target.json`、`region/Control.json`：每站预热及 8 轮的 HTTP 状态、时长、curl 状态码。
- 本次不测试 WebRTC、IPv6 或吞吐量；未读取 TrojanX 内部选中节点的策略日志。
