// Clash_rule.js V6.2【无 ProxyIP 版】（以 V6.1 为底，只做精简与整理，不含 ProxyIP 绑定模块）
//   ① 个人维护区（自定义域名 / 固定节点域名）集中到文件顶部
//   ② 静态表与纯函数移到 main 外；main 内按 节点处理 → DNS → 规则集 → 策略组 → 规则 排列
//   ③ 删除订阅 proxy-server-nameserver-policy 的 rule-set 搬运机制（订阅带该写法时对应键直接丢弃）
//   ④ 修正若干注释；QUIC 嗅探仅在未屏蔽 QUIC 时开启
//   ⑤ 完整移除 ProxyIP 绑定模块（节点 path 不会被追加任何参数）；需要时改用「ProxyIP 精简版」
// 需较新的 mihomo 内核；首次启动联网下载规则集，在日志确认全部下载成功。
// 使用本脚本后，请关闭 FlClash 里的"DNS 覆写"，DNS 配置已全部写进脚本。
// 屏蔽 QUIC / 屏蔽 STUN / BT 直连 已写进本脚本，请勿再在 FlClash"附加规则"里重复开启。

// ════════════════════════════════════════
// 一、个人维护区（常改的都在这里，升级脚本后只需抄回这一段）
// ════════════════════════════════════════

// 自定义域名：命中后优先于所有规则集。
// CUSTOM_PROXY 走节点选择（DNS 走海外 DoH），CUSTOM_DIRECT 直连（DNS 走国内 DoH）。
// 写主域名即可，自动匹配其子域名。".cn" 域名基本都是国内站，作为直连兜底
const CUSTOM_PROXY = ["bilibili.tv", "biliintl.com", "bilicdn1.com"];
const CUSTOM_DIRECT = ["cn"];

// 固定节点基础设施域名：ECH 配置查询域名 + 节点的 SNI / WS Host 域名，固定走国内 DoH，不依赖脚本能否看见节点。
// proxy-providers 订阅时节点不可见，必须靠这里写死，否则 ECH 配置查询会经代理出站，形成循环。
const FIXED_NODE_DOMAINS = [
    "cloudflare-ech.com",
    "edge-2.jiayusail.de5.net",
    "qifei.jiayusail.dynv6.net",
    "xiaoshuo-877.pages.dev"   // CFNext 的 Pages 域名
];

// ════════════════════════════════════════
// 二、可调参数
// ════════════════════════════════════════

const REGION_MIN_NODES = 2;        // 达到该值才建组；provider 订阅时节点不可见，不参与判断
const RS_INTERVAL = 604800;        // 规则集更新周期：一周
const CN_DNS_DOH = [
    "https://223.5.5.5/dns-query",
    "https://doh.pub/dns-query"
];
const CN_DNS_PLAIN = ["223.5.5.5", "119.29.29.29"];
const OVERSEAS_DNS_DOH = [
    "https://1.1.1.1/dns-query#RULES",
    "https://8.8.8.8/dns-query#RULES"
];
// 节点域名解析（proxy-server-nameserver）：排在最前，订阅自带的 DNS 仍保留在其后
const PROXY_SERVER_DNS = [
    "https://dns.alidns.com/dns-query",
    "https://doh.pub/dns-query"
];
const TEST_URL_PROXY = "https://www.gstatic.com/generate_204";
const PREFER_H3 = false;          // DoH 并发尝试 HTTP/3：UDP 被限速或不支持时反而更慢

// 测速组参数（地区组 + 自动选择组共用）
const AUTO_TEST_INTERVAL = 300;   // 每 5 分钟（300 秒）自动测速一次
const AUTO_TEST_TOLERANCE = 30;   // 容差 30ms：新节点比当前节点快超过该值才切换

// ── 固定组名（改名只需改这里，规则、DNS 校验、各组引用会同步） ──
// 非隐藏组会作为顶部导航标签显示，标签直接显示组名；所以"手动选择"拆成两个组：
// MANUAL_GROUP（纯文字、可见，在里面挑节点）；MANUAL_ENTRY（带 emoji、隐藏，只在"节点选择"里显示为卡片）
const PROXY_GROUP = "节点选择";     // 唯一顶层入口，规则的兜底出口
const MANUAL_GROUP = "手动选择";    // 手动挑任意节点
const MANUAL_ENTRY = "✋手动选择";   // 节点选择里显示的入口卡片（隐藏组，指向手动选择）
const AUTO_GROUP = "⚡自动选择";    // 不分国家，全部节点里自动选延迟最低的
const DIRECT_GROUP = "🏠直连连接";  // 成员是内建 DIRECT

// ── 传输层 / 附加规则开关 ──
// 拒绝 UDP 443 迫使浏览器立刻回退 TCP。EdgeTunnel（Workers/Pages）节点不转发 UDP，建议开启
const BLOCK_QUIC = true;
// 拒绝 STUN 常用 UDP 端口：避免 WebRTC 绕过代理暴露真实 IP；网页视频通话/在线会议受影响时改为 false
const BLOCK_STUN = true;
// BT tracker / PT 站点域名直连：避免占用节点额度。只能匹配域名，直连 IP 的 BT 对等流量不受影响
const BT_DIRECT = true;

// ── 可选规则开关（关闭后对应规则集不会被创建和下载） ──
// Microsoft 组默认选"直连连接"；需要走代理时在面板的 Microsoft 组里手动切回"节点选择"
const MICROSOFT_DEFAULT_DIRECT = true;
// 下载站直连（666OS Download）：迅雷、各类下载 CDN 不占节点流量
const DOWNLOAD_DIRECT = true;
// 追踪 / 统计域名拦截（666OS Tracking）：与 category-ads-all 互补
const BLOCK_TRACKING = true;
// 国内 App 广告拦截（AWAvenue-Ads-Rule）：与 category-ads-all 有重叠、偶有误杀，默认关闭，需要时改 true
const BLOCK_AWAVENUE = false;

// ── 规则集下载地址（统一用 jsdmirror 镜像，格式：/gh/用户/仓库@分支/路径） ──
const RS_CDN = "https://cdn.jsdmirror.com/gh";
const RS_BASE = `${RS_CDN}/MetaCubeX/meta-rules-dat@meta/geo`;
const RS_666OS = `${RS_CDN}/666OS/rules@release/mihomo`;
const RS_AWAVENUE = `${RS_CDN}/TG-Twilight/AWAvenue-Ads-Rule@main/Filters`;
const RS_FAKEIP_FILTER = `${RS_CDN}/wwqgtxx/clash-rules@release/fakeip-filter.mrs`;

// ── IPv6 / 双栈 ──
// on：强制开启 IPv6（DNS 解析 AAAA、IPv6 fake-ip），不受 FlClash 里 IPv6 开关影响
// follow：跟随客户端 IPv6 开关；off：强制关闭
// 节点出站拨号的 IP 版本：开启 IPv6 时用 ipv4-prefer（先 IPv4，不通再 IPv6），关闭时用 dual。
// 只决定"客户端连节点服务器"用哪个协议栈，不影响最终出口（出口由 Worker 决定）。
// ipv6-prefer 曾导致优选域名节点 TCP 通但 TLS/WS 握手被重置，且不会回退 IPv4，节点大面积测速失败
const IPV6_MODE = "on";

// ── DNS 防泄漏 ──
// false：海外域名一律走脚本里的海外 DoH（经代理出站），忽略订阅自带的 nameserver，避免查询被带回国内 DNS
const TRUST_SUB_NAMESERVER = false;

// ── 订阅配置清理 ──
// 订阅里带有 listeners / authentication / skip-auth-prefixes 时直接删除（其引用的策略组名在本脚本重建后已不存在，
// 留着会让内核报错，也可能把本机变成对局域网开放的代理）
const SANITIZE_SUB_CONFIG = true;

// ── 节点命名 ──
// true：本地节点统一命名为"国旗 简称 原名"，如 🇭🇰 HK 联通优选；已有国旗/简称的保留并去重
// 没有任何地区信息的节点（如"三网优选"）会在名称前加一个图标
const RENAME_NODES = true;

// ════════════════════════════════════════
// 三、静态表与通用函数（无需修改）
// ════════════════════════════════════════

// 节点名里的信息类关键词（剩余流量、到期时间、群链接等），这些不该单独成为可选节点
// 另含 URL / "失联"：像"防失联页 https://…"这类提示节点同样不该出现在节点列表里
const excludeFilter =
    "(?i)(https?://|失联|剩余|官网|套餐|流量|到期|过期|更新|刷新|订阅|群|网址|客服|欢迎|加入|Expire|Traffic|Reset|(^|[^A-Za-z0-9])(\\d+(\\.\\d+)?\\s*(GB|TB)|\\d+\\s*Days?)([^A-Za-z0-9]|$))";

// 内核用 Go 正则，JS 侧不支持 (?i) 前缀
const toJsRegex = goStyleRegex =>
    new RegExp(goStyleRegex.replace(/^\(\?i\)/, ""), "i");

const excludeRe = toJsRegex(excludeFilter);

// 两位国家代码 → 国旗 emoji（区域指示符）
const flagOf = code =>
    String.fromCodePoint(
        0x1f1e6 + code.charCodeAt(0) - 65,
        0x1f1e6 + code.charCodeAt(1) - 65
    );

// 地区表。regex 两处共用同一串：内核 group filter 是 Go 正则（(?i) 合法），JS 侧经 toJsRegex 转换
// name：两位国家代码（用于节点命名与匹配）；cn：中文名，用于节点选择里的地区组命名
const regions = [
    {
        name: "AE",
        cn: "阿联酋",
        regex: "(?i)(阿联酋|阿聯酋|迪拜|阿布扎比|🇦🇪|(^|[^A-Za-z])UAE([^A-Za-z]|$)|Emirates|Dubai)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/ae.svg"
    },
    {
        name: "AR",
        cn: "阿根廷",
        regex: "(?i)(阿根廷|布宜诺斯艾利斯|🇦🇷|(^|[^A-Za-z])AR([^A-Za-z]|$)|(^|[^A-Za-z])ARG([^A-Za-z]|$)|Argentina)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/ar.svg"
    },
    {
        name: "AU",
        cn: "澳大利亚",
        regex: "(?i)(澳大利亚|澳大利亞|澳洲|悉尼|墨尔本|墨爾本|🇦🇺|(^|[^A-Za-z])AU([^A-Za-z]|$)|(^|[^A-Za-z])AUS([^A-Za-z]|$)|Australia|Sydney|Melbourne)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/au.svg"
    },
    {
        name: "BD",
        cn: "孟加拉",
        regex: "(?i)(孟加拉|孟加拉國|达卡|達卡|🇧🇩|(^|[^A-Za-z])BD([^A-Za-z]|$)|(^|[^A-Za-z])BGD([^A-Za-z]|$)|Bangladesh|Dhaka)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/bd.svg"
    },
    {
        name: "BR",
        cn: "巴西",
        regex: "(?i)(巴西|圣保罗|聖保羅|🇧🇷|(^|[^A-Za-z])BR([^A-Za-z]|$)|(^|[^A-Za-z])BRA([^A-Za-z]|$)|Brazil|Brasil|SaoPaulo)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/br.svg"
    },
    {
        name: "CA",
        cn: "加拿大",
        regex: "(?i)(加拿大|多伦多|多倫多|温哥华|溫哥華|🇨🇦|(^|[^A-Za-z])CA([^A-Za-z]|$)|(^|[^A-Za-z])CAN([^A-Za-z]|$)|Canada|Toronto|Vancouver)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/ca.svg"
    },
    {
        name: "CH",
        cn: "瑞士",
        regex: "(?i)(瑞士|苏黎世|蘇黎世|🇨🇭|(^|[^A-Za-z])CH([^A-Za-z]|$)|(^|[^A-Za-z])CHE([^A-Za-z]|$)|Switzerland|Zurich)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/ch.svg"
    },
    {
        name: "DE",
        cn: "德国",
        regex: "(?i)(德国|德國|法兰克福|法蘭克福|🇩🇪|(^|[^A-Za-z])DE([^A-Za-z]|$)|(^|[^A-Za-z])DEU([^A-Za-z]|$)|Germany|Frankfurt)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/de.svg"
    },
    {
        name: "FI",
        cn: "芬兰",
        regex: "(?i)(芬兰|芬蘭|赫尔辛基|赫爾辛基|🇫🇮|(^|[^A-Za-z])FI([^A-Za-z]|$)|(^|[^A-Za-z])FIN([^A-Za-z]|$)|Finland|Helsinki)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/fi.svg"
    },
    {
        name: "FR",
        cn: "法国",
        regex: "(?i)(法国|法國|巴黎|🇫🇷|(^|[^A-Za-z])FR([^A-Za-z]|$)|(^|[^A-Za-z])FRA([^A-Za-z]|$)|France|Paris)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/fr.svg"
    },
    {
        name: "GB",
        cn: "英国",
        regex: "(?i)(英国|英國|伦敦|倫敦|🇬🇧|(^|[^A-Za-z])UK([^A-Za-z]|$)|(^|[^A-Za-z])GB([^A-Za-z]|$)|(^|[^A-Za-z])GBR([^A-Za-z]|$)|United[ -]?Kingdom|England|London)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/gb.svg"
    },
    {
        name: "HK",
        cn: "香港",
        regex: "(?i)(香港|🇭🇰|(^|[^A-Za-z])HK([^A-Za-z]|$)|(^|[^A-Za-z])HKG([^A-Za-z]|$)|Hong[ -]?Kong)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/hk.svg"
    },
    {
        name: "ID",
        cn: "印尼",
        regex: "(?i)(印度尼西亚|印度尼西亞|印尼|雅加达|雅加達|🇮🇩|Indonesia|Jakarta|(^|[^A-Za-z])ID([^A-Za-z]|$)|(^|[^A-Za-z])IDN([^A-Za-z]|$))",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/id.svg"
    },
    {
        // 印度([^尼]|$) 只排除"印度尼西亚"；含独立 token IN 的节点名会同时命中 ID 与 IN，内核各组 filter 相互独立、无组间排除
        name: "IN",
        cn: "印度",
        regex: "(?i)(印度([^尼]|$)|新德里|孟买|孟買|班加罗尔|班加羅爾|🇮🇳|(^|[^A-Za-z])India([^A-Za-z]|$)|Mumbai|Delhi|Bangalore|(^|[^A-Za-z])IN([^A-Za-z]|$)|(^|[^A-Za-z])IND([^A-Za-z]|$))",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/in.svg"
    },
    {
        name: "JP",
        cn: "日本",
        regex: "(?i)(日本|东京|東京|大阪|🇯🇵|(^|[^A-Za-z])JP([^A-Za-z]|$)|(^|[^A-Za-z])JPN([^A-Za-z]|$)|Japan)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/jp.svg"
    },
    {
        name: "KR",
        cn: "韩国",
        regex: "(?i)(韩国|韓國|南韩|南韓|首尔|首爾|🇰🇷|(^|[^A-Za-z])KR([^A-Za-z]|$)|(^|[^A-Za-z])KOR([^A-Za-z]|$)|Korea)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/kr.svg"
    },
    {
        name: "LV",
        cn: "拉脱维亚",
        regex: "(?i)(拉脱维亚|拉脫維亞|里加|🇱🇻|(^|[^A-Za-z])LV([^A-Za-z]|$)|(^|[^A-Za-z])LVA([^A-Za-z]|$)|Latvia|Riga)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/lv.svg"
    },
    {
        name: "MY",
        cn: "马来西亚",
        regex: "(?i)(马来西亚|馬來西亞|吉隆坡|🇲🇾|(^|[^A-Za-z])MY([^A-Za-z]|$)|(^|[^A-Za-z])MYS([^A-Za-z]|$)|Malaysia)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/my.svg"
    },
    {
        name: "NL",
        cn: "荷兰",
        regex: "(?i)(荷兰|荷蘭|阿姆斯特丹|🇳🇱|(^|[^A-Za-z])NL([^A-Za-z]|$)|(^|[^A-Za-z])NLD([^A-Za-z]|$)|Netherlands|Amsterdam)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/nl.svg"
    },
    {
        name: "PH",
        cn: "菲律宾",
        regex: "(?i)(菲律宾|菲律賓|马尼拉|馬尼拉|宿务|宿霧|🇵🇭|(^|[^A-Za-z])PH([^A-Za-z]|$)|(^|[^A-Za-z])PHL([^A-Za-z]|$)|Philippines|Manila|Cebu)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/ph.svg"
    },
    {
        name: "PL",
        cn: "波兰",
        regex: "(?i)(波兰|波蘭|华沙|華沙|🇵🇱|(^|[^A-Za-z])PL([^A-Za-z]|$)|(^|[^A-Za-z])POL([^A-Za-z]|$)|Poland|Warsaw)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/pl.svg"
    },
    {
        name: "RU",
        cn: "俄罗斯",
        regex: "(?i)(俄罗斯|俄羅斯|莫斯科|🇷🇺|(^|[^A-Za-z])RU([^A-Za-z]|$)|(^|[^A-Za-z])RUS([^A-Za-z]|$)|Russia|Moscow)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/ru.svg"
    },
    {
        name: "SE",
        cn: "瑞典",
        regex: "(?i)(瑞典|斯德哥尔摩|斯德哥爾摩|🇸🇪|(^|[^A-Za-z])SE([^A-Za-z]|$)|(^|[^A-Za-z])SWE([^A-Za-z]|$)|Sweden|Stockholm)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/se.svg"
    },
    {
        name: "SG",
        cn: "新加坡",
        regex: "(?i)(新加坡|狮城|獅城|🇸🇬|(^|[^A-Za-z])SG([^A-Za-z]|$)|(^|[^A-Za-z])SGP([^A-Za-z]|$)|Singapore)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/sg.svg"
    },
    {
        name: "TH",
        cn: "泰国",
        regex: "(?i)(泰国|泰國|曼谷|🇹🇭|Thailand|Bangkok|(^|[^A-Za-z])TH([^A-Za-z]|$)|(^|[^A-Za-z])THA([^A-Za-z]|$))",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/th.svg"
    },
    {
        name: "TR",
        cn: "土耳其",
        regex: "(?i)(土耳其|伊斯坦布尔|🇹🇷|(^|[^A-Za-z])TR([^A-Za-z]|$)|(^|[^A-Za-z])TUR([^A-Za-z]|$)|Turkey|Türkiye|Istanbul)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/tr.svg"
    },
    {
        name: "TW",
        cn: "台湾",
        regex: "(?i)(台湾|台灣|台北|新北|🇹🇼|(^|[^A-Za-z])TW([^A-Za-z]|$)|(^|[^A-Za-z])TWN([^A-Za-z]|$)|Taiwan)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/tw.svg"
    },
    {
        name: "US",
        cn: "美国",
        regex: "(?i)(美国|美國|洛杉矶|洛杉磯|圣何塞|聖何塞|硅谷|矽谷|西雅图|西雅圖|纽约|紐約|🇺🇸|(^|[^A-Za-z])US([^A-Za-z]|$)|(^|[^A-Za-z])USA([^A-Za-z]|$)|United[ -]?States)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/us.svg"
    },
    {
        name: "VN",
        cn: "越南",
        regex: "(?i)(越南|河内|河內|胡志明|🇻🇳|(^|[^A-Za-z])VN([^A-Za-z]|$)|(^|[^A-Za-z])VNM([^A-Za-z]|$)|Viet[ -]?Nam|Hanoi|Ho[ -]?Chi[ -]?Minh)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/vn.svg"
    }
];

// 节点选择里地区组的显示名："国旗+中文名+节点"，如 🇭🇰香港节点。
// 仅用于策略组名；节点命名与地区匹配仍用两位代码
regions.forEach(region => {
    region.label = flagOf(region.name) + region.cn + "节点";
});

// App 组名单与图标；direct: true 的组默认选中"直连连接"
const apps = [
    { name: "AI", icon: "openai.png" },
    { name: "Apple", icon: "apple.png" },
    {
        name: "GitHub",
        icon: "https://cdn.jsdmirror.com/gh/kanwox/Stash-Conf@main/github.png"
    },
    { name: "Google", icon: "google.png" },
    {
        name: "Microsoft",
        icon: "microsoft.png",
        direct: MICROSOFT_DEFAULT_DIRECT
    },
    { name: "Spotify", icon: "spotify.png" },
    { name: "Telegram", icon: "telegram.png" },
    { name: "TikTok", icon: "tiktok.png" },
    { name: "TV", icon: "netflix.png" },
    { name: "Twitch", icon: "twitch.png" },
    { name: "X", icon: "x.png" },
    { name: "YouTube", icon: "youtube.png" }
];

// 脚本固定生成的组名（App 名由 apps 派生）
const OWN_GROUPS = [
    PROXY_GROUP,
    AUTO_GROUP,
    MANUAL_GROUP,
    MANUAL_ENTRY,
    DIRECT_GROUP,
    ...apps.map(app => app.name)
];

// 内建策略名。RULES 由内核单独特判：DNS 连接按路由规则出站，不查策略表
const BUILTIN_POLICIES = new Set([
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "COMPATIBLE",
    "PASS",
    "PASS-RULE",
    "GLOBAL",
    "RULES"
]);

// 内核中节点与策略组共享同一命名空间，且要求节点名唯一：与自建组/地区组/内建 outbound 重名的节点、
// 以及订阅内的重名节点，都会让内核启动直接报错，main 里会抢先改名。地区组以 label 命名，保留名随之使用 label
const RESERVED_NAMES = new Set([
    ...OWN_GROUPS,
    ...regions.map(region => region.label),
    ...BUILTIN_POLICIES
]);

// 部分客户端脚本引擎无 console.warn：统一经此降级输出，避免 TypeError 中断转换
const warnLog = (...args) => {
    if (typeof console === "undefined") return;
    if (typeof console.warn === "function") console.warn(...args);
    else if (typeof console.log === "function") console.log(...args);
};

const isPlainObject = value =>
    value &&
    typeof value === "object" &&
    !Array.isArray(value);

const asPlainObject = value => (isPlainObject(value) ? value : {});

const stringList = value => {
    if (value === undefined || value === null) return [];

    const list = Array.isArray(value) ? value : [value];

    return list
        .filter(item => typeof item === "string")
        .map(item => item.trim())
        .filter(Boolean);
};

// 自定义域名清洗：去空白、去首部 "." 或 "+."、去重
const cleanDomains = list => [
    ...new Set(
        stringList(list)
            .map(domain => domain.replace(/^(\+\.|\.)/, ""))
            .filter(Boolean)
    )
];

// ── 节点命名与地区识别 ──
// 命名格式："国旗 简称 原名"，如 🇭🇰 HK 联通优选。
// 识别顺序：①名字里已有的国旗；②去掉 []/()/【】内容后，取名字中最靠前的地区关键词（避免
// "[singapore.com]" 这类括号里的域名把港节点误判成新加坡）；③完整名字。
// 带有表中没有的国旗（如 🇨🇳 CN）的节点、信息类节点（剩余流量、群链接等）保持原样。
// 注意：proxy-providers 订阅的节点脚本期不可见，无法改名
const CODE_ALIASES = {
    AE: ["UAE"], AR: ["ARG"], AU: ["AUS"], BD: ["BGD"], BR: ["BRA"],
    CA: ["CAN"], CH: ["CHE"], DE: ["DEU"], FI: ["FIN"], FR: ["FRA"],
    GB: ["UK", "GBR"], HK: ["HKG"], ID: ["IDN"], IN: ["IND"],
    JP: ["JPN"], KR: ["KOR"], LV: ["LVA"], MY: ["MYS"], NL: ["NLD"],
    PH: ["PHL"], PL: ["POL"], RU: ["RUS"], SE: ["SWE"], SG: ["SGP"],
    TH: ["THA"], TR: ["TUR"], TW: ["TWN"], US: ["USA"], VN: ["VNM"]
};

const regionByCode = new Map(
    regions.map(region => [region.name, region])
);
const regionRegexes = regions.map(region => ({
    code: region.name,
    re: toJsRegex(region.regex)
}));

// 取名字里出现的全部国旗对应的两位代码（按出现顺序）。不用带 u 标志的正则，兼容性更好
const flagCodesIn = name => {
    const cps = Array.from(name).map(ch => ch.codePointAt(0));
    const found = [];

    for (let i = 0; i + 1 < cps.length; i++) {
        if (
            cps[i] >= 0x1f1e6 &&
            cps[i] <= 0x1f1ff &&
            cps[i + 1] >= 0x1f1e6 &&
            cps[i + 1] <= 0x1f1ff
        ) {
            found.push(
                String.fromCharCode(
                    cps[i] - 0x1f1e6 + 65,
                    cps[i + 1] - 0x1f1e6 + 65
                )
            );
            i++;
        }
    }

    return found;
};

const BRACKET_RE = /\[[^\]]*\]|【[^】]*】|\([^)]*\)|（[^）]*）/g;

const earliestRegion = text => {
    let best = null;

    for (const item of regionRegexes) {
        const match = item.re.exec(text);

        if (match && (best === null || match.index < best.index)) {
            best = { code: item.code, index: match.index };
        }
    }

    return best ? best.code : "";
};

const detectRegion = name => {
    const flags = flagCodesIn(name);

    for (const code of flags) {
        if (regionByCode.has(code)) return code;
    }

    // 带有表中没有的国旗：尊重原标注，不改名
    if (flags.length > 0) return "";

    return (
        earliestRegion(name.replace(BRACKET_RE, " ")) ||
        earliestRegion(name)
    );
};

const formatNodeName = (name, code) => {
    const flag = flagOf(code);
    const tokens = [code, ...(CODE_ALIASES[code] || [])];
    const tokenRe = new RegExp(
        "(^|[^A-Za-z0-9])(?:" + tokens.join("|") + ")(?![A-Za-z])",
        "gi"
    );

    // 括号内容（如 [wsrv.nl 188ms] 里的域名）先换成占位符、清理完再还原：
    // 否则域名后缀 .nl / .us / .sg 会被当成地区简称误删（wsrv.nl → wsrv.）
    const bracketParts = [];
    const masked = name.replace(BRACKET_RE, part => {
        bracketParts.push(part);
        return "\uE000" + (bracketParts.length - 1) + "\uE001";
    });

    // 去掉括号外已有的同地区国旗与简称，避免重复；其余原名原样保留
    const rest = masked
        .split(flag)
        .join(" ")
        .replace(tokenRe, "$1 ")
        .replace(/\s+/g, " ")
        .replace(/^[\s\-_|·•,，、:：/.]+/, "")
        .replace(/[\s\-_|·•]+$/, "")
        .trim()
        .replace(
            /\uE000(\d+)\uE001/g,
            (_, index) => bracketParts[Number(index)]
        );

    return rest ? flag + " " + code + " " + rest : flag + " " + code;
};

// 无地区信息节点：名称前加图标
const NO_REGION_ICONS = ["🔀", "🌐", "🔗", "📡", "🛜", "✅", "🌀", "🔰"];

const hasNoRegionIcon = name =>
    NO_REGION_ICONS.some(icon => name.startsWith(icon + " "));

// 按节点名哈希取图标：每个节点图标不同，同名节点每次刷新结果一致
const pickNoRegionIcon = name => {
    let h = 0;

    for (let i = 0; i < name.length; i++) {
        h = (h * 31 + name.charCodeAt(i)) >>> 0;
    }

    return NO_REGION_ICONS[h % NO_REGION_ICONS.length];
};

// ── DNS 清洗通用函数 ──

// 节点解析 DNS 不得经代理/策略组出站，否则形成"需要节点才能解析节点"的循环
const stripProxyRefs = entry => {
    const s = String(entry);
    const hash = s.indexOf("#");

    if (hash === -1) return s;

    const opts = s
        .slice(hash + 1)
        .split("&")
        .map(part => part.trim())
        .filter(part => part !== "" && part.includes("="));

    return opts.length > 0
        ? s.slice(0, hash) + "#" + opts.join("&")
        : s.slice(0, hash);
};

const stripProxyRefsPolicy = policy => {
    const out = {};

    for (const key of Object.keys(policy)) {
        out[key] = stringList(policy[key]).map(stripProxyRefs);
    }

    return out;
};

// 订阅 DNS 里指向已重建规则集/内建 geo 的键会硬报错或触发额外下载，一律丢弃
const isDanglingKey = key => /^(rule-set|geosite|geoip):/i.test(key);

// 域名是否为纯域名（非 IP）
const isDomainName = value =>
    typeof value === "string" &&
    /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(value) &&
    !/^\d+(\.\d+){3}$/.test(value);

// 仅这三类协议有 client-fingerprint 字段；hysteria2 / tuic / ss 内核未提供该字段
const FP_OK = ["vless", "vmess", "trojan"];

// provider 版本的指纹注入（节点运行时才出现，只能用 override 表达式），与 main 里本地节点的判定条件必须等价
// 用 .["client-fingerprint"] 而非 .client-fingerprint：避免 yq/jq 把连字符 '-' 误解析为减法
const FP_EXPR =
    '(select(.type == "trojan" or ((.type == "vless" or .type == "vmess") and (.tls == true or has("reality-opts")))) | select(has("client-fingerprint") | not) | .["client-fingerprint"]) = "chrome"';

// 规范化为表达式数组；类型非法返回 null，调用方原样保留该 provider、不做注入
const normalizeOverrideExpr = raw => {
    if (raw === undefined || raw === null) return [];

    if (typeof raw === "string") {
        return raw.length > 0 ? [raw] : [];
    }

    if (Array.isArray(raw)) {
        if (raw.some(item => typeof item !== "string")) {
            return null;
        }

        return raw.filter(item => item.length > 0);
    }

    return null;
};

// ════════════════════════════════════════
// 四、主函数
// ════════════════════════════════════════

function main(params) {
    if (!params || typeof params !== "object") params = {};
    if (!Array.isArray(params.proxies)) params.proxies = [];

    // 内核要求节点名非空且唯一，空名/非法条目会让整份配置启动失败，直接丢弃
    params.proxies = params.proxies.filter(
        proxy =>
            proxy &&
            typeof proxy.name === "string" &&
            proxy.name !== ""
    );

    // 记住面板手动选择与 fake-ip 缓存；订阅已设置的项以订阅为准
    params.profile = Object.assign(
        { "store-selected": true, "store-fake-ip": true },
        isPlainObject(params.profile) ? params.profile : {}
    );

    // 订阅自身是否使用代理集合（决定地区组是全量还是按节点数筛选）
    const subHasProviders =
        Object.keys(params["proxy-providers"] || {}).length > 0;

    // ── 1. 基础选项 ──
    Object.assign(params, {
        "unified-delay": true,
        // 并发尝试多个 IP，取最快握手
        "tcp-concurrent": true,
        // 不匹配进程名：省掉每条连接的进程查找
        "find-process-mode": "off",
        // TCP 保活（秒）：平衡移动端电量与 NAT 会话活性，避免被中间网关静默重置
        "keep-alive-idle": 300,
        "keep-alive-interval": 30
    });

    // IPv6：由 IPV6_MODE 决定（默认 on，不受客户端开关影响）
    const ipv6Enabled =
        IPV6_MODE === "on"
            ? true
            : IPV6_MODE === "off"
              ? false
              : params.ipv6 === true;
    params.ipv6 = ipv6Enabled;
    // 节点出站 IP 版本，说明见顶部 IPV6_MODE
    const defaultIpVersion = ipv6Enabled ? "ipv4-prefer" : "dual";

    // 内核已移除该字段并会在启动时报错
    delete params["global-client-fingerprint"];

    if (SANITIZE_SUB_CONFIG) {
        delete params.listeners;
        delete params.authentication;
        delete params["skip-auth-prefixes"];
    }

    const sniffProtocols = {
        HTTP: {
            ports: [80, "8080-8880"],
            "override-destination": true
        },
        TLS: {
            ports: [443, 8443]
        }
    };

    // 已屏蔽 UDP 443 时 QUIC 嗅探无意义，只在未屏蔽时开启
    if (!BLOCK_QUIC) {
        sniffProtocols.QUIC = { ports: [443, 8443] };
    }

    params.sniffer = {
        enable: true,
        "force-dns-mapping": true,
        // 纯 IP 流量强制嗅探：应用绕过系统 DNS 直连 IP 时，从 TLS SNI / HTTP Host 还原域名参与分流，避免兜底误判
        "parse-pure-ip": true,
        "override-destination": true,
        sniff: sniffProtocols,
        "skip-domain": [
            // 米家设备的 SNI 恰好是 "Mijia Cloud"（非域名），按精确匹配跳过嗅探
            "Mijia Cloud",
            "+.apple.com",
            "+.openai.com",
            "+.oaistatic.com",
            "+.oaiusercontent.com",
            "+.chatgpt.com"
        ]
    };

    // ── 2. 节点处理：命名 → 去重 → 出站 IP 版本 / 指纹 ──
    const proxyRegion = new Map();   // 节点对象 → 地区代码（仅本地节点）
    const renamedFrom = new Map();   // 旧名 → 新名，用于修补 dialer-proxy 引用

    if (RENAME_NODES) {
        params.proxies.forEach(proxy => {
            if (
                proxy.type === "direct" ||
                proxy.type === "reject" ||
                excludeRe.test(proxy.name)
            ) {
                return;
            }

            const code = detectRegion(proxy.name);

            if (!code) {
                // 带有表中没有的国旗：尊重原标注，不加图标
                if (flagCodesIn(proxy.name).length > 0) return;

                // 已经加过图标：不重复加
                if (hasNoRegionIcon(proxy.name)) return;

                const iconName =
                    pickNoRegionIcon(proxy.name) + " " + proxy.name;

                if (!renamedFrom.has(proxy.name)) {
                    renamedFrom.set(proxy.name, iconName);
                }

                proxy.name = iconName;
                return;
            }

            const newName = formatNodeName(proxy.name, code);

            proxyRegion.set(proxy, code);

            if (newName !== proxy.name) {
                if (!renamedFrom.has(proxy.name)) {
                    renamedFrom.set(proxy.name, newName);
                }

                proxy.name = newName;
            }
        });

        // 链式代理：dialer-proxy 按名字引用其它节点，改名后同步更新
        params.proxies.forEach(proxy => {
            const dialer = proxy["dialer-proxy"];

            if (typeof dialer === "string" && renamedFrom.has(dialer)) {
                proxy["dialer-proxy"] = renamedFrom.get(dialer);
            }
        });
    }

    // 去重 / 避开保留名
    const usedProxyNames = new Set();

    params.proxies.forEach(proxy => {
        let name = proxy.name;

        if (RESERVED_NAMES.has(name) || usedProxyNames.has(name)) {
            const reservedHit = RESERVED_NAMES.has(name);
            let candidate = name;
            let suffix = 0;

            do {
                suffix++;
                candidate = reservedHit
                    ? "节点·" + name + (suffix > 1 ? "·" + suffix : "")
                    : name + "·" + suffix;
            } while (
                RESERVED_NAMES.has(candidate) ||
                usedProxyNames.has(candidate)
            );

            name = candidate;
            proxy.name = name;
        }

        usedProxyNames.add(name);
    });

    // 本地节点：出站 IP 版本与 TLS 指纹（不覆盖订阅已有的取值）
    params.proxies.forEach(proxy => {
        if (
            proxy.type !== "direct" &&
            !("ip-version" in proxy)
        ) {
            proxy["ip-version"] = defaultIpVersion;
        }

        if (
            FP_OK.indexOf(proxy.type) !== -1 &&
            !proxy["client-fingerprint"]
        ) {
            const usesTLS =
                proxy.type === "trojan" ||
                proxy.tls === true ||
                proxy["reality-opts"];

            if (usesTLS) {
                proxy["client-fingerprint"] = "chrome";
            }
        }
    });

    // provider 节点：健康检查 + 出站 IP 版本 + 指纹（脚本期不可见，只能用 override 表达式）
    Object.entries(params["proxy-providers"] || {}).forEach(
        ([name, provider]) => {
            if (!provider || typeof provider !== "object") {
                return;
            }

            // 组的 url 健康检查只测 proxies 字段成员，provider 节点须靠 provider 自身的 health-check 产出延迟数据，
            // 否则地区 url-test 组拿不到延迟、永远选中第一个节点。enable 强制开启，其余项以订阅为准
            const subHealthCheck = isPlainObject(
                provider["health-check"]
            )
                ? provider["health-check"]
                : {};

            provider["health-check"] = Object.assign(
                {
                    enable: true,
                    url: TEST_URL_PROXY,
                    interval: 300,
                    timeout: 5000,
                    "expected-status": 204,
                    lazy: true
                },
                subHealthCheck,
                { enable: true }
            );

            const override = provider.override;

            if (
                override !== undefined &&
                override !== null &&
                (typeof override !== "object" ||
                    Array.isArray(override))
            ) {
                return;
            }

            const existingExpr = normalizeOverrideExpr(
                (override || {})["override-expr"]
            );

            if (existingExpr === null) return;

            // 保留上游表达式顺序；脚本指纹表达式最多出现一次（订阅每次刷新重跑本段）
            const finalExpr = existingExpr.includes(FP_EXPR)
                ? existingExpr
                : [...existingExpr, FP_EXPR];

            const mergedOverride = Object.assign(
                {},
                override || {}
            );

            if (!("ip-version" in mergedOverride)) {
                mergedOverride["ip-version"] = defaultIpVersion;
            }

            mergedOverride["override-expr"] = finalExpr;
            provider.override = mergedOverride;
        }
    );

    // ── 3. 地区统计 ──
    // direct / reject 类型不进任何可选组，与下方组的 exclude-type 保持一致
    const allProxies = params.proxies.filter(
        proxy => proxy.type !== "direct" && proxy.type !== "reject"
    );

    // 本地订阅且已统一命名：地区组按"国旗 简称"前缀精确匹配，不再依赖模糊正则，
    // 避免 "[canadatype.com]" 这类括号里的域名把节点拉进别的地区组
    const anchoredGroups = RENAME_NODES && !subHasProviders;

    const matchedRegions = regions.filter(region => {
        let count = 0;

        if (anchoredGroups) {
            for (const proxy of allProxies) {
                if (proxyRegion.get(proxy) === region.name) {
                    count++;
                    if (count >= REGION_MIN_NODES) return true;
                }
            }

            return false;
        }

        const regex = toJsRegex(region.regex);

        for (const proxy of allProxies) {
            if (
                regex.test(proxy.name) &&
                !excludeRe.test(proxy.name)
            ) {
                count++;
                if (count >= REGION_MIN_NODES) return true;
            }
        }

        return false;
    });

    // provider 订阅时脚本期看不到节点，维持全量地区组
    const activeRegions = subHasProviders ? regions : matchedRegions;
    const hasActiveRegions = activeRegions.length > 0;
    const regionLabels = activeRegions.map(region => region.label);

    // ── 4. DNS ──
    // 订阅 DNS 里指向已重建策略组的 "#组名" 后缀原样并入会硬报错，须清洗；
    // 不可迁移字段一律静默丢弃、以脚本配置为准，永远输出完整配置

    // 取自实际会建组的 activeRegions，避免引用到节点不足未建组的地区
    const REGION_NAMES = new Set(regionLabels);

    // 本地节点名并入合法引用集："#节点名" 指定解析节点是内核支持的写法，不识别会被误剥；provider 订阅下该集合为空
    const PROXY_NAMES = new Set(
        allProxies.map(proxy => proxy && proxy.name).filter(Boolean)
    );

    // 校验 DNS 条目尾部 "#目标"：合法整条保留，指向已删除对象则剥掉并补 #RULES
    const refValid = ref =>
        BUILTIN_POLICIES.has(ref) ||
        OWN_GROUPS.indexOf(ref) !== -1 ||
        REGION_NAMES.has(ref) ||
        PROXY_NAMES.has(ref);

    // 内核解析 # 后片段（config.parseNameServer）：按 "&" 分段，含 "=" 的是参数（h3=/ecs= 等），
    // 不含的是目标名，被误当网卡名会运行期静默失败；故只校验裸段、参数段原样保留
    const stripDanglingRef = entry => {
        const s = String(entry);
        const hash = s.indexOf("#");

        if (hash === -1) return s;

        const parts = s
            .slice(hash + 1)
            .split("&")
            .map(part => part.trim())
            .filter(Boolean)
            .filter(part => part.includes("=") || refValid(part));

        if (parts.length > 0) return s.slice(0, hash) + "#" + parts.join("&");

        // 无有效引用时补 #RULES 交给路由决定，避免剥成裸 URL 直连（DNS 直连会同时招致污染与泄漏）
        return s.slice(0, hash) + "#RULES";
    };

    const deriveSubDNS = rawDNS => {
        const subDNS = asPlainObject(rawDNS);

        const subPSN = stringList(
            subDNS["proxy-server-nameserver"]
        ).map(stripDanglingRef);

        const subNS = stringList(subDNS.nameserver).map(
            stripDanglingRef
        );

        const subPolicy = Object.assign(
            {},
            asPlainObject(subDNS["nameserver-policy"])
        );

        // fake-ip-filter 仅在缺省/blacklist 时继承；whitelist/rule 语义不同，继承会反转过滤含义，固定输出 blacklist
        const modeRaw = subDNS["fake-ip-filter-mode"];
        const mode =
            typeof modeRaw === "string"
                ? modeRaw.trim().toLowerCase()
                : "";

        const subFilter =
            mode === "" || mode === "blacklist"
                ? stringList(subDNS["fake-ip-filter"]).filter(
                      item => !isDanglingKey(item)
                  )
                : [];

        // 逐键清洗：通吃键架空分流、指向重建规则集/内建 geo 的键会硬报错，均丢弃；值同样清洗悬空引用
        for (const key of Object.keys(subPolicy)) {
            if (
                key === "+." ||
                key === "*" ||
                key === "+" ||
                isDanglingKey(key)
            ) {
                delete subPolicy[key];
                continue;
            }

            subPolicy[key] = stringList(subPolicy[key]).map(
                stripDanglingRef
            );
        }

        // proxy-server-nameserver-policy：rule-set / geosite / geoip 键一律丢弃（本脚本重建了规则集）；
        // 通吃键不删（此字段只作用于节点域名，脚本不在此注入自身条目）
        const rawPSNPolicy = asPlainObject(
            subDNS["proxy-server-nameserver-policy"]
        );
        const subPSNPolicy = {};

        for (const key of Object.keys(rawPSNPolicy)) {
            if (isDanglingKey(key)) continue;

            subPSNPolicy[key] = stringList(rawPSNPolicy[key]).map(
                stripDanglingRef
            );
        }

        let proxyServerNameserver;
        let proxyServerNameserverPolicy;

        if (subPSN.length > 0) {
            // 机场显式设置节点 DNS 时独占使用，不混入公共 DNS
            proxyServerNameserver = [
                ...new Set(subPSN.map(stripProxyRefs))
            ];
            proxyServerNameserverPolicy =
                stripProxyRefsPolicy(subPSNPolicy);
        } else {
            // 未显式设置节点 DNS 时，以普通域名解析策略为迁移来源，避免新补公共 DNS 屏蔽机场专用解析
            const hasFallbackComplexity =
                subDNS.fallback !== undefined ||
                subDNS["fallback-filter"] !== undefined;

            if (hasFallbackComplexity) {
                // fallback 属"路由选出 DNS 出口"的复杂行为，无法在单一列表等价表达；忽略，节点解析直接用国内 DoH
                proxyServerNameserver = [...CN_DNS_DOH];
                proxyServerNameserverPolicy = undefined;
            } else if (
                subNS.length > 0 ||
                Object.keys(subPolicy).length > 0
            ) {
                // 按原优先关系迁入节点解析（policy 优先于 nameserver 不变）
                proxyServerNameserver =
                    subNS.length > 0
                        ? [...new Set(subNS.map(stripProxyRefs))]
                        : [...CN_DNS_DOH];

                proxyServerNameserverPolicy =
                    Object.keys(subPolicy).length > 0
                        ? stripProxyRefsPolicy(subPolicy)
                        : undefined;
            } else {
                // 无任何可继承解析信息，用默认公共 DNS
                proxyServerNameserver = [...CN_DNS_DOH];
                proxyServerNameserverPolicy = undefined;
            }
        }

        return {
            subDNS,
            subNS,
            subPolicy,
            subFilter,
            proxyServerNameserver,
            proxyServerNameserverPolicy
        };
    };

    let dnsInfo;

    try {
        const rawDNS = params.dns;

        if (
            rawDNS !== undefined &&
            rawDNS !== null &&
            !isPlainObject(rawDNS)
        ) {
            throw new Error("dns 字段不是对象");
        }

        dnsInfo = deriveSubDNS(rawDNS);
    } catch (error) {
        warnLog(
            "[Clash_rule.js] 读取订阅 DNS 时出错（" +
                (error && error.message
                    ? error.message
                    : String(error)) +
                "），已放弃订阅 DNS，改用脚本默认配置。"
        );

        dnsInfo = deriveSubDNS(null);
    }

    const {
        subDNS,
        subNS,
        subPolicy,
        subFilter,
        proxyServerNameserver,
        proxyServerNameserverPolicy
    } = dnsInfo;

    // DNS 层 IPv6：与全局 IPv6 开关一致（AAAA 解析、IPv6 fake-ip 段同步开启/关闭）
    const dnsIPv6 = ipv6Enabled;

    // 自定义域名的 DNS 策略：代理域名走海外 DoH（经代理出站，解析结果适合海外出口），直连域名走国内 DoH
    const customDnsPolicy = {};

    cleanDomains(CUSTOM_PROXY).forEach(domain => {
        customDnsPolicy["+." + domain] = [...OVERSEAS_DNS_DOH];
    });

    cleanDomains(CUSTOM_DIRECT).forEach(domain => {
        customDnsPolicy["+." + domain] = [...CN_DNS_DOH];
    });

    // 节点自身依赖的域名（ECH 配置查询名、SNI/servername、WS/XHTTP Host）：要在代理就绪前就能解析，
    // 走国内 DoH，避免"需要节点才能解析节点"的循环；这些域名只涉及节点基础设施，不是用户访问流量
    const nodeDomainPolicy = {};

    // 固定域名：不依赖脚本能否看见节点（provider 订阅同样生效）
    FIXED_NODE_DOMAINS.forEach(value => {
        if (isDomainName(value)) {
            nodeDomainPolicy[value.toLowerCase()] = [...CN_DNS_DOH];
        }
    });

    params.proxies.forEach(proxy => {
        const ws = isPlainObject(proxy["ws-opts"]) ? proxy["ws-opts"] : {};
        const headers = isPlainObject(ws.headers) ? ws.headers : {};
        const xhttp = isPlainObject(proxy["xhttp-opts"]) ? proxy["xhttp-opts"] : {};
        const ech = isPlainObject(proxy["ech-opts"]) ? proxy["ech-opts"] : {};

        [
            proxy.servername,
            proxy.sni,
            ech["query-server-name"],
            headers.Host,
            headers.host,
            xhttp.host
        ].forEach(value => {
            if (isDomainName(value)) {
                nodeDomainPolicy[value.toLowerCase()] = [...CN_DNS_DOH];
            }
        });
    });

    params.dns = {
        enable: true,
        // 固定回环 + 非特权端口：订阅常见 0.0.0.0:53，被系统 DNS 占住会导致内核启动失败；
        // 要给局域网设备当 DNS 用时改这一行并自行确认端口与防火墙
        listen: "127.0.0.1:1053",
        ipv6: dnsIPv6,
        "prefer-h3": PREFER_H3,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        // IPv6 fake-ip 段（仅 DNS 启用 IPv6 时输出）：沿用 Clash 默认的 ULA 段，与常见家用局域网段不冲突
        ...(dnsIPv6
            ? { "fake-ip-range6": "fdfe:dcba:9876::/64" }
            : {}),
        "cache-algorithm": "arc",
        // 显式声明，不依赖内核默认值
        "fake-ip-filter-mode": "blacklist",
        // DNS 出站按路由规则走：#RULES 才能生效，海外 DoH 经代理、国内 DoH 直连，是防泄漏的关键
        "respect-rules": true,
        // 保留订阅自带的 hosts 能力
        "use-hosts":
            typeof subDNS["use-hosts"] === "boolean"
                ? subDNS["use-hosts"]
                : true,
        "use-system-hosts":
            typeof subDNS["use-system-hosts"] === "boolean"
                ? subDNS["use-system-hosts"]
                : true,
        ...(isPlainObject(subDNS.hosts)
            ? { hosts: subDNS.hosts }
            : {}),
        // 前段为 real-ip 刚需：局域网、NTP、连通性探测、游戏平台（对时拿假地址会失败，连带影响 TLS 校验）
        "fake-ip-filter": [
            ...new Set([
                "+.lan",
                "+.local",
                "localhost.ptlogin2.qq.com",
                "+.msftconnecttest.com",
                "+.msftncsi.com",
                "+.ntp.org",
                "+.xboxlive.com",
                "+.playstation.net",
                "+.xbox.com",
                "xbox.ipv6.microsoft.com",
                "+.srv.nintendo.net",
                "time.windows.com",
                "time.apple.com",
                // STUN 通配：域名含 stun 段的全部豁免假地址
                "+.stun.*",
                "+.stun.*.*",
                "+.stun.*.*.*",
                "+.stun.*.*.*.*",
                // 由脚本自带的规则集兜底，防手维护清单漏项
                "rule-set:cn-domain",
                "rule-set:private-domain",
                "rule-set:fakeip-filter",
                ...subFilter
            ])
        ],
        // 引导 DNS：仅解析其它 DoH 服务器域名（如 doh.pub）；明文 IP 最快且不依赖证书校验
        "default-nameserver": [...CN_DNS_PLAIN],
        "proxy-server-nameserver": [
            ...new Set([...PROXY_SERVER_DNS, ...proxyServerNameserver])
        ],
        ...(proxyServerNameserverPolicy &&
        Object.keys(proxyServerNameserverPolicy).length > 0
            ? {
                  "proxy-server-nameserver-policy":
                      proxyServerNameserverPolicy
              }
            : {}),
        // 海外域名：默认用海外 DoH，#RULES 按路由规则出站（未匹配项经 MATCH 落节点选择），查询不经本地运营商。
        // TRUST_SUB_NAMESERVER=true 时才改用订阅自带的 nameserver
        nameserver:
            TRUST_SUB_NAMESERVER && subNS.length > 0
                ? [...new Set(subNS)]
                : [...OVERSEAS_DNS_DOH],
        // DIRECT 命中且未被 nameserver-policy 覆盖的域名（未收录 cn-domain 的冷门国内站点）用国内 DoH：
        // 加密传输，不被运营商看到查询内容，也避免退回节点选择去查海外
        "direct-nameserver": [...CN_DNS_DOH],
        // true：DIRECT 命中域名先走 nameserver-policy，未被覆盖才落到 direct-nameserver
        "direct-nameserver-follow-policy": true,
        // 顺序即优先级：域名键在前、rule-set 键在后。自定义域名与节点域名必须排在 rule-set:cn-domain 之前，
        // 否则 bilibili.tv 这类被 cn 列表收录的域名仍会先被国内 DNS 解析
        "nameserver-policy": Object.assign(
            {},
            subPolicy,
            nodeDomainPolicy,
            customDnsPolicy,
            {
                "rule-set:private-domain": ["system://"],
                "rule-set:ads-domain": ["rcode://name_error"],
                "rule-set:cn-domain": [...CN_DNS_DOH]
            }
        )
    };

    // ── 5. 规则集 ──
    // MetaCubeX 官方拆分库，全 mrs（地址常量见顶部 RS_BASE）
    const domainProvider = name => ({
        type: "http",
        behavior: "domain",
        format: "mrs",
        url: `${RS_BASE}/geosite/${name}.mrs`,
        path: `./ruleset/geosite-${name}.mrs`,
        interval: RS_INTERVAL
    });

    const ipProvider = name => ({
        type: "http",
        behavior: "ipcidr",
        format: "mrs",
        url: `${RS_BASE}/geoip/${name}.mrs`,
        path: `./ruleset/geoip-${name}.mrs`,
        interval: RS_INTERVAL
    });

    // 非 MetaCubeX 来源的规则集（666OS / AWAvenue / wwqgtxx）：自行指定地址、行为、格式与缓存文件名
    const extraProvider = (url, behavior, format, file) => ({
        type: "http",
        behavior,
        format,
        url,
        path: `./ruleset/${file}`,
        interval: RS_INTERVAL
    });

    // 引用名 → 官方分类名
    const DOMAIN_SETS = {
        "private-domain": "private",
        "ads-domain": "category-ads-all",
        "youtube-domain": "youtube",
        "twitch-domain": "twitch",
        "twitter-domain": "twitter",
        "tiktok-domain": "tiktok",
        "telegram-domain": "telegram",
        "github-domain": "github",
        "ai-domain": "category-ai-!cn",
        "netflix-domain": "netflix",
        "disney-domain": "disney",
        "primevideo-domain": "primevideo",
        "appletv-domain": "apple-tvplus",
        "hbo-domain": "hbo",
        "spotify-domain": "spotify",
        "google-domain": "google",
        "apple-domain": "apple",
        "microsoft-domain": "microsoft",
        "proxy-domain": "geolocation-!cn",
        "cn-domain": "cn"
    };

    // BT：公共 tracker + PT 站点域名（仅 BT_DIRECT 开启时才建规则集并下载）
    if (BT_DIRECT) {
        DOMAIN_SETS["bt-tracker-domain"] = "category-public-tracker";
        DOMAIN_SETS["bt-pt-domain"] = "category-pt";
    }

    const IP_SETS = {
        "private-ip": "private",
        "telegram-ip": "telegram",
        "cn-ip": "cn"
    };

    // 清空重建（订阅原有的 rule-providers 不保留）
    params["rule-providers"] = {};

    Object.keys(DOMAIN_SETS).forEach(key => {
        params["rule-providers"][key] = domainProvider(DOMAIN_SETS[key]);
    });

    Object.keys(IP_SETS).forEach(key => {
        params["rule-providers"][key] = ipProvider(IP_SETS[key]);
    });

    // 社区维护的 fake-ip 豁免清单（wwqgtxx/clash-rules，官方未收录），供 dns.fake-ip-filter 引用
    params["rule-providers"]["fakeip-filter"] = extraProvider(
        RS_FAKEIP_FILTER,
        "domain",
        "mrs",
        "fakeip-filter.mrs"
    );

    // 可选规则集：开关关闭则不创建，规则段里也同步不生成对应规则
    if (DOWNLOAD_DIRECT) {
        params["rule-providers"]["download-domain"] = extraProvider(
            `${RS_666OS}/domain/Download.mrs`,
            "domain",
            "mrs",
            "666os-download.mrs"
        );
    }

    if (BLOCK_TRACKING) {
        params["rule-providers"]["tracking-domain"] = extraProvider(
            `${RS_666OS}/domain/Tracking.mrs`,
            "domain",
            "mrs",
            "666os-tracking.mrs"
        );
    }

    if (BLOCK_AWAVENUE) {
        params["rule-providers"]["awavenue-ads"] = extraProvider(
            `${RS_AWAVENUE}/AWAvenue-Ads-Rule-Clash.yaml`,
            "domain",
            "yaml",
            "awavenue-ads.yaml"
        );
    }

    // ── 6. 策略组 ──
    const groups = [];

    // 节点选择：唯一顶层入口。顺序：自动选择（全部节点最低延迟）→ 各国家地区组 → 手动选择 → 直连连接
    groups.push({
        name: PROXY_GROUP,
        type: "select",
        icon: "https://cdn.jsdmirror.com/gh/Koolson/Qure@63be653774a6a83cd8e475a7b65f1ed68b9a0093/IconSet/Color/Proxy.png",
        proxies: hasActiveRegions
            ? [AUTO_GROUP, ...regionLabels, MANUAL_ENTRY, DIRECT_GROUP]
            : [AUTO_GROUP, MANUAL_ENTRY, DIRECT_GROUP]
    });

    // 自动选择：不分国家，所有可用节点里自动选延迟最低的（区别于下方按国家分的地区测速组）
    groups.push({
        name: AUTO_GROUP,
        type: "url-test",
        // 隐藏：不单独占顶部导航标签，只作为成员显示在"节点选择"里，测速功能不受影响
        hidden: true,
        icon: "https://cdn.jsdmirror.com/gh/Koolson/Qure@63be653774a6a83cd8e475a7b65f1ed68b9a0093/IconSet/Color/Auto.png",
        "include-all": true,
        "exclude-type": "direct|reject",
        "exclude-filter": excludeFilter,
        // 订阅节点全被过滤时用 REJECT 兜底，而不是留空组
        "empty-fallback": "REJECT",
        url: TEST_URL_PROXY,
        interval: AUTO_TEST_INTERVAL,
        tolerance: AUTO_TEST_TOLERANCE,
        lazy: true,
        timeout: 5000,
        "max-failed-times": 5,
        "expected-status": 204
    });

    // 手动选择：收全部节点（排除 direct / reject 与信息类节点），给不想选地区的人兜底
    groups.push({
        name: MANUAL_GROUP,
        type: "select",
        icon: "https://cdn.jsdmirror.com/gh/Koolson/Qure@63be653774a6a83cd8e475a7b65f1ed68b9a0093/IconSet/Color/Static.png",
        "include-all": true,
        "exclude-type": "direct|reject",
        "exclude-filter": excludeFilter,
        "empty-fallback": "REJECT"
    });

    // 手动选择入口：隐藏，不占标签；只在"节点选择"里显示为带图标的卡片，选中它即使用"手动选择"页里当前选的节点
    groups.push({
        name: MANUAL_ENTRY,
        type: "select",
        hidden: true,
        icon: "https://cdn.jsdmirror.com/gh/Koolson/Qure@63be653774a6a83cd8e475a7b65f1ed68b9a0093/IconSet/Color/Static.png",
        proxies: [MANUAL_GROUP]
    });

    // 隐藏直连组：仅供内部选择引用；与内建 DIRECT 区分——这是名为"直连连接"的策略组，成员才是 DIRECT
    groups.push({
        name: DIRECT_GROUP,
        type: "select",
        hidden: true,
        icon: "https://cdn.jsdmirror.com/gh/Koolson/Qure@63be653774a6a83cd8e475a7b65f1ed68b9a0093/IconSet/Color/Direct.png",
        proxies: ["DIRECT"]
    });

    // 普通 App 组：默认选中"节点选择"；direct 组（Microsoft）把"直连连接"排第一，默认直连
    const appProxiesList = [PROXY_GROUP, DIRECT_GROUP, ...regionLabels];
    const appProxiesDirectFirst = [DIRECT_GROUP, PROXY_GROUP, ...regionLabels];

    // App 策略组：proxies 给切换目标，include-all 再塞入订阅节点本身，两者缺一不可
    apps.forEach(app => {
        const icon = app.icon.startsWith("http")
            ? app.icon
            : `https://cdn.jsdmirror.com/gh/shindgew/WHATSINStash@main/icon/${app.icon}`;

        groups.push({
            name: app.name,
            type: "select",
            icon,
            proxies: app.direct ? appProxiesDirectFirst : appProxiesList,
            "include-all": true,
            "exclude-type": "direct|reject",
            "exclude-filter": excludeFilter
        });
    });

    // 地区测速组（全隐藏）：组名为"国旗+中文名+节点"（如 🇭🇰香港节点）；
    // 本地订阅且已统一命名时按"国旗 简称"前缀精确匹配，否则用 Go 正则原串（(?i) 合法）
    activeRegions.forEach(region => {
        groups.push({
            name: region.label,
            type: "url-test",
            hidden: true,
            icon: region.icon,
            "include-all": true,
            "exclude-type": "direct|reject",
            filter: anchoredGroups
                ? "(?i)^" + flagOf(region.name) + " " + region.name + "( |$)"
                : region.regex,
            "exclude-filter": excludeFilter,
            // provider 订阅下可能一个节点都匹配不上，用 REJECT 兜底而不是留空组
            "empty-fallback": "REJECT",
            url: TEST_URL_PROXY,
            interval: AUTO_TEST_INTERVAL,
            tolerance: AUTO_TEST_TOLERANCE,
            lazy: true,
            timeout: 5000,
            "max-failed-times": 5,
            "expected-status": 204
        });
    });

    // 本地订阅下若全部节点被 excludeFilter 过滤，「手动选择」将解析为空并回落 REJECT（静默断网），
    // 转换期能确定时留一条日志；provider 订阅节点不可见，此检查覆盖不到，只能看内核日志
    if (!subHasProviders) {
        const usableCount = allProxies.filter(
            proxy => !excludeRe.test(proxy.name)
        ).length;

        if (usableCount === 0) {
            warnLog(
                "[Clash_rule.js] 订阅节点全部被 excludeFilter 过滤，「手动选择」组将为空并回落 REJECT，网络将不可用；请检查 excludeFilter 或节点命名。"
            );
        }
    }

    params["proxy-groups"] = groups;

    // ── 7. 规则 ──
    // 自定义域名规则：生成 DOMAIN-SUFFIX 规则
    const buildCustomRules = (list, policy) =>
        cleanDomains(list).map(
            domain => `DOMAIN-SUFFIX,${domain},${policy}`
        );

    // 规则自上而下先命中先决定，顺序即优先级，五层：
    //   1. 私网 / 广告 / 追踪（避免内网域名被后面的规则带去代理）
    //   2. 传输层兜底（NTP、QUIC / STUN 阻断、BT 直连；必须排在应用分流前，否则 UDP/443 被应用规则抢先）
    //   3. 自定义域名（个人维护，优先于所有规则集，用来纠正规则集的误判）
    //   4. 应用分流（Download 直连排在其后、通用代理域名之前：应用服务先命中，剩下的下载站再直连）
    //   5. 国内直连 → MATCH 兜底
    // cn-domain 排在 Google / Apple / Microsoft 之后：让应用分流先吃掉，避免其国内 CDN 域名被直连截胡
    params.rules = [
        "RULE-SET,private-domain,DIRECT",
        "RULE-SET,private-ip,DIRECT,no-resolve",
        "RULE-SET,ads-domain,REJECT",
        ...(BLOCK_TRACKING ? ["RULE-SET,tracking-domain,REJECT"] : []),
        ...(BLOCK_AWAVENUE ? ["RULE-SET,awavenue-ads,REJECT"] : []),
        // 系统对时优先于业务分流：很多节点丢弃/限制 UDP 123，时间偏差会连带导致全局 TLS 证书校验失败
        "AND,((DST-PORT,123),(NETWORK,UDP)),DIRECT",
        ...(BLOCK_QUIC
            ? ["AND,((DST-PORT,443),(NETWORK,UDP)),REJECT"]
            : []),
        // STUN：3478/3479 为标准端口，19302-19309 为 Google STUN；DST-PORT 用 "/" 分隔多值、"-" 表示区间
        ...(BLOCK_STUN
            ? [
                  "AND,((NETWORK,UDP),(DST-PORT,3478/3479/19302-19309)),REJECT"
              ]
            : []),
        ...(BT_DIRECT
            ? [
                  "RULE-SET,bt-tracker-domain,DIRECT",
                  "RULE-SET,bt-pt-domain,DIRECT"
              ]
            : []),

        // 自定义域名：直连在前、代理在后，同一域名同时出现在两处时以直连为准
        ...buildCustomRules(CUSTOM_DIRECT, "DIRECT"),
        ...buildCustomRules(CUSTOM_PROXY, PROXY_GROUP),

        "RULE-SET,youtube-domain,YouTube",
        "RULE-SET,twitch-domain,Twitch",
        "RULE-SET,twitter-domain,X",
        "RULE-SET,tiktok-domain,TikTok",
        "RULE-SET,telegram-domain,Telegram",
        "RULE-SET,telegram-ip,Telegram,no-resolve",
        "RULE-SET,ai-domain,AI",
        "RULE-SET,github-domain,GitHub",

        "RULE-SET,netflix-domain,TV",
        "RULE-SET,disney-domain,TV",
        "RULE-SET,primevideo-domain,TV",
        "RULE-SET,appletv-domain,TV",
        "RULE-SET,hbo-domain,TV",
        "RULE-SET,spotify-domain,Spotify",

        "RULE-SET,google-domain,Google",
        "RULE-SET,apple-domain,Apple",
        "RULE-SET,microsoft-domain,Microsoft",

        ...(DOWNLOAD_DIRECT ? ["RULE-SET,download-domain,DIRECT"] : []),

        `RULE-SET,proxy-domain,${PROXY_GROUP}`,

        "RULE-SET,cn-domain,DIRECT",
        // no-resolve：Fake-IP 域名直接跳过，避免未收录站点进 MATCH 前被海外 nameserver 解析引入延迟
        "RULE-SET,cn-ip,DIRECT,no-resolve",

        `MATCH,${PROXY_GROUP}`
    ];

    return params;
}

if (typeof module !== "undefined") {
    module.exports = main;
    module.exports.main = main;
}
