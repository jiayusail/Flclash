// Clash_rule.js V6.5 家宽链式前置版（无 Proxy IP，支持导入前置节点）
// mihomo / FlClash 覆写脚本，主要功能：
//   · 节点统一命名为"国旗 简称 原名"，按国家地区自动建测速组，另有全部节点自动选择与手动选择；
//     命名规范：国旗 + 两位简称排在最前；国家三字码（HKG / USA / UK 等）和机场三字码（SJC、NRT、SIN 等）
//     只用于识别地区，不显示在名字里（名字里除了机场码没有别的文字时才保留，避免节点名全部变成一样）；
//     去掉重复的国旗 / 简称 / 三字码时，它们前后的分隔符一起去掉；家宽节点名里重复的简称同样去掉；
//     名字完全相同且没有序号的节点自动加序号（移动优选 → 移动优选-1、移动优选-2），
//     名字末尾有括号（）()［］[]【】时，序号排在括号前面（圣何塞-1 (147ms)）
//   · DNS：fake-ip + 国内外分流；海外域名经代理用海外 DoH 解析，节点自身域名固定走国内 DoH；
//     订阅显式设置的节点解析 DNS 独占使用，未设置时用脚本默认值
//   · 规则：广告 / 追踪拦截，QUIC / STUN 屏蔽，BT 直连，常用应用分流，国内直连，其余走节点选择
//   · 同时支持本地节点订阅与 proxy-providers 订阅；节点按名称自然排序
//   · 稳定性：节点改名与策略组重建后统一校验 dialer-proxy；DNS 只保留实际存在的引用，
//     失效引用回退 #RULES，家宽拨号目标失效或存在歧义时回退「隧道前置」并记录日志
//   · 前置节点导入：个人维护区的 IMPORT_LINKS 直接粘贴节点文本即可，支持
//       - IP / 域名 [:端口] #备注（优选工具结果；#备注作为节点名；uuid / path / host / SNI 等参数借用订阅里的机场节点，
//         订阅里有多个域名时按 IMPORT_DOMAIN_MODE 轮流分配）
//       - vless:// trojan:// hysteria2:// 分享链接（V2rayNG 等客户端复制的链接，参数取自链接本身）
//     IMPORT_MODE 决定导入的节点只给"隧道前置"引用（front），还是同时加入所有策略组（all）；
//     导入的节点与订阅里已有的节点重复时自动去重（只引用订阅里那个，不会重复出现）；
//     FRONT_APPEND_COUNT 可把订阅里排在前面的 N 个节点追加进前置节点池（只给前置组多引用一次，原来的组不受影响）
//   · 家宽模式（CFNext OpenVPN 节点）链式代理：
//       - 导入的节点作为前置节点，自动注入订阅
//       - 给每个家宽 OpenVPN 节点补上 dialer-proxy: 隧道前置
//       - 「隧道前置」组：手动选择用哪个前置节点（默认「前置自动」取延迟最低）
//       - 「家宽出口」组：选择落地的家宽节点；链路 = 本机 → 前置节点 → 家宽节点
//       - 家宽出口内含全局"家宽自动"和按实际节点生成的地区测速组，也可手动选择单个节点
//       - 家宽节点命名为"国旗 简称 清理后原名"（如 🇯🇵 JP 家宽-2），不参与普通地区组 / 自动选择 / 手动选择
// 使用说明：
//   · 需较新的 mihomo 内核；首次启动需联网下载规则集，请在日志确认全部下载成功
//   · 使用本脚本后请关闭 FlClash 的"DNS 覆写"，DNS 配置已全部写进脚本
//   · 屏蔽 QUIC / STUN、BT 直连已写进本脚本，请勿再在 FlClash"附加规则"里重复开启
//   · 本版不含 ProxyIP 绑定，节点 path 不会被改写
//   · 脚本不含任何机场域名 / uuid：裸 IP 行借用订阅里的参数，分享脚本前清空 IMPORT_LINKS 即可

// ════════════════════════════════════════
// 一、个人维护区（常改的都在这里）
// ════════════════════════════════════════

// 自定义域名，优先于所有规则集；写主域名即可，自动匹配子域名。
// CUSTOM_PROXY 走节点选择（DNS 用海外 DoH），CUSTOM_DIRECT 直连（DNS 用国内 DoH）。
// ".cn" 作为国内站直连兜底
const CUSTOM_PROXY = ["bilibili.tv", "biliintl.com", "bilicdn1.com"];
const CUSTOM_DIRECT = ["cn"];

// 节点基础设施域名（ECH 配置查询域名、节点 SNI / WS Host 域名），固定走国内 DoH。
// proxy-providers 订阅时脚本看不到节点，必须在这里写死，否则 ECH 查询会经代理出站形成循环
const FIXED_NODE_DOMAINS = [
    "cloudflare-ech.com"
];

// 导入节点：一行一个，空行和 // 开头的行会被忽略；同一行里用逗号 / 分号（中文、英文都行）隔开多个也能识别。
// 支持的格式：
//   1) IP 或域名，#后面是节点名（端口可省略；IPv6 要加方括号）：
//        104.24.0.232:8443#香港优选IPv4
//        www.visa.cn#优选域名
//        [2606:4700::]:2053#美国优选IPv6
//      这类行只有地址，uuid / path / host / SNI / ECH 等参数自动借用订阅里的 ws+tls 节点
//      （优先 vless，其次 trojan；同一个域名只算一个；ECH 查询名 cloudflare-ech.com 不会被当作节点域名）；
//      订阅里找不到这样的节点时，这类行会被跳过并在日志里提示。多个域名怎么分配见 IMPORT_DOMAIN_MODE
//   2) 分享链接（参数取自链接本身，不借用订阅）：
//        vless://uuid@host:port?type=ws&security=tls&sni=...&host=...&path=...&fp=chrome#节点名
//        trojan://password@host:port?type=ws&security=tls&sni=...&host=...&path=...#节点名
//        hysteria2://password@host:port?sni=...&insecure=1#节点名
// 节点名：#后面的备注（支持 URL 编码），脚本会按"国旗 简称 原名"统一命名；没写备注时用地址当名字
// 去重：类型、服务器地址、端口、SNI / Host 都和订阅里某个节点相同的，不再新增节点，直接引用订阅里那个
// （此时节点名沿用订阅里的名字）；同一个节点在这里写了多遍也只算一个
const IMPORT_LINKS = `
// 默认留空。留空时前置节点池取订阅里排在前面的节点（见 FRONT_APPEND_COUNT）。
// 在下面粘贴你的节点（示例，去掉行首的 // 即可使用）：
// 104.24.0.232:8443#香港优选IPv4
// [2606:4700::]:2053#美国优选IPv6
// www.visa.cn#优选域名
`;

// 导入节点的去向：
//   "front"：只给"隧道前置"组引用（前置节点池），不进地区组 / 自动选择 / 手动选择 / 应用组；
//            订阅里没有家宽节点时没有"隧道前置"组，会自动改为加入所有策略组
//   "all"：既进"隧道前置"组，也和订阅里的普通节点一样加入所有策略组
// 注意：hysteria2 是 UDP 协议，不适合作前置节点（前置节点要承载 OpenVPN 家宽的拨号流量），
// 想用 hy2 当普通节点请用 "all"
const IMPORT_MODE = "front";

// 裸 IP / 域名行借用订阅里的机场参数时，订阅里有多个不同域名怎么分配：
//   "rotate"：按域名在订阅里出现的顺序轮流分配（3 个域名、5 个 IP → 域名1、2、3、1、2），
//             每个域名连同它自己的 uuid / path 一起使用；结果固定，每次更新订阅都一样
//   "first"：所有裸 IP 都用订阅里第一个域名
const IMPORT_DOMAIN_MODE = "rotate";

// 把订阅里排在前面的 N 个节点（按订阅原顺序，跳过信息类节点和 hysteria / tuic 等 UDP 协议节点）
// 追加进"隧道前置"的节点池。这些节点本来就是订阅里的普通节点，仍然留在原来的所有策略组里，
// 只是"隧道前置"多引用它们一次，所以没有"只给前置 / 给所有组"的区别。
// "auto"：导入区有节点时不追加（0），导入区留空时追加 10 个；也可以直接写数字，0 = 不追加，20 = 追加 20 个。
// 只对本地节点订阅有效（proxy-providers 订阅里脚本看不到节点）。
// 注意："前置自动"在整个节点池里按延迟选最低，追加的节点可能比你自己导入的更快而被选中；
// 想让自己导入的节点优先，就设为 0
// 当前固定追加订阅原顺序中的前 60 个合格节点；如需恢复自动模式可改回 "auto"
const FRONT_APPEND_COUNT = 60;

// 追加订阅节点时只取这些地区的节点（两位或三字国家代码都行，如 HK / HKG、JP / JPN、US / USA、UK / GBR，
// 写成数组或用逗号隔开的字符串都行，大小写不限）。
// ["all"] 或留空 = 所有地区。数量 FRONT_APPEND_COUNT 是筛选后的总数，按订阅原顺序取前 N 个。
// 支持的地区：AE AR AU BD BR CA CH DE EE FI FR GB HK ID IN JP KR LV MY NL PH PL RO RU SE SG TH TR TW US VN（以及它们的三字码）；
// 识别不到地区的节点在指定了具体地区时不会被追加
const FRONT_APPEND_REGIONS = ["all"];

// ════════════════════════════════════════
// 二、可调参数
// ════════════════════════════════════════

const REGION_MIN_NODES = 2;        // 地区节点数达到该值才建组（provider 订阅时节点不可见，不参与判断）
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
// 节点域名解析的默认 DNS：仅订阅自己没有设置 proxy-server-nameserver 时使用；
// 订阅显式设置了就独占使用订阅的（同组 DNS 并发竞速，混用会让公共 DNS 抢答机场专线解析）
const PROXY_SERVER_DNS = [
    "https://dns.alidns.com/dns-query",
    "https://doh.pub/dns-query"
];
const TEST_URL_PROXY = "https://www.gstatic.com/generate_204";
const PREFER_H3 = false;          // DoH 是否并发尝试 HTTP/3：UDP 被限速或不支持时反而更慢

// 测速组参数（地区组与自动选择组共用）
const AUTO_TEST_INTERVAL = 300;   // 自动测速间隔（秒）
const AUTO_TEST_TOLERANCE = 50;   // 容差（ms）：新节点比当前节点快超过该值才切换

// 家宽测速参数：OpenVPN 经隧道拨号，握手慢，间隔放长、容差放大
const HOME_TEST_INTERVAL = 600;
const HOME_TEST_TOLERANCE = 50;

// 固定组名（改名只需改这里，规则、DNS 校验、各组引用同步生效）。
// 非隐藏组会作为顶部导航标签显示，所以"手动选择"拆成两个组：
// MANUAL_GROUP 可见，在里面挑节点；MANUAL_ENTRY 隐藏，只在"节点选择"里显示为入口卡片
const PROXY_GROUP = "节点选择";     // 唯一顶层入口，规则的兜底出口
const MANUAL_GROUP = "手动选择";    // 手动挑任意节点
const MANUAL_ENTRY = "✋手动选择";   // "节点选择"里的手动选择入口（隐藏组）
const AUTO_GROUP = "⚡自动选择";    // 不分国家，全部节点里自动选延迟最低的
const DIRECT_GROUP = "🏠直连连接";  // 成员是内建 DIRECT

// 家宽相关组名。TUNNEL_GROUP 是家宽节点 dialer-proxy 的取值（脚本会自动给家宽节点补上）
const TUNNEL_GROUP = "隧道前置";    // 前置节点选择组（可见，手动选第一跳）
const FRONT_AUTO = "前置自动";      // 前置节点里自动选延迟最低（隐藏，作为"隧道前置"的第一个选项）
const HOME_AUTO = "家宽自动";       // 家宽节点中自动选延迟最低（隐藏）
const HOME_GROUP = "家宽出口";      // 手动挑家宽节点（落地），出现在"节点选择"和各应用组里
// 过滤 UDP 家宽节点：前置节点是 EdgeTunnel（ws，只走 TCP），无法转发 OpenVPN 的 UDP 握手，
// UDP 家宽节点经前置后必然连不通，开启后直接从订阅里剔除（判定：udp: true 或 proto: udp）
const FILTER_UDP_HOME = true;
// 家宽节点名关键词（CFNext 家宽节点原名均含"家宽"，如 家宽JP、家宽KR-2；改名后为"🇯🇵 JP 家宽JP"，所以匹配名称任意位置）
const HOME_FILTER = "(?i)家宽";
// 自动选择 / 手动选择 / 地区组 / 应用组统一排除的节点类型（家宽 OpenVPN 节点不参与）
const NODE_EXCLUDE_TYPE = "direct|reject|openvpn";

// 传输层 / 附加规则开关
// 拒绝 UDP 443，迫使浏览器回退 TCP。EdgeTunnel（Workers / Pages）节点不转发 UDP，建议开启
const BLOCK_QUIC = true;
// 拒绝 STUN 常用 UDP 端口，防止 WebRTC 绕过代理暴露真实 IP；网页视频通话 / 在线会议受影响时改为 false
const BLOCK_STUN = true;
// BT tracker / PT 站点域名直连，避免占用节点额度（只能匹配域名，直连 IP 的 BT 对等流量不受影响）
const BT_DIRECT = true;

// 可选规则开关（关闭后对应规则集不会被创建和下载）
// Microsoft 组默认选"直连连接"，需要代理时在面板里手动切回"节点选择"
const MICROSOFT_DEFAULT_DIRECT = true;
// 下载站直连（666OS Download）：迅雷、各类下载 CDN 不占节点流量
const DOWNLOAD_DIRECT = true;
// 追踪 / 统计域名拦截（666OS Tracking），与 category-ads-all 互补
const BLOCK_TRACKING = true;
// 国内 App 广告拦截（AWAvenue-Ads-Rule）：与 category-ads-all 有重叠、偶有误杀，默认关闭
const BLOCK_AWAVENUE = false;

// 规则集下载地址（统一用 jsdmirror 镜像）
const RS_CDN = "https://cdn.jsdmirror.com/gh";
const RS_BASE = `${RS_CDN}/MetaCubeX/meta-rules-dat@meta/geo`;
const RS_666OS = `${RS_CDN}/666OS/rules@release/mihomo`;
const RS_AWAVENUE = `${RS_CDN}/TG-Twilight/AWAvenue-Ads-Rule@main/Filters`;
const RS_FAKEIP_FILTER = `${RS_CDN}/wwqgtxx/clash-rules@release/fakeip-filter.mrs`;

// IPv6 / 双栈
// on：强制开启（DNS 解析 AAAA、IPv6 fake-ip），不受客户端 IPv6 开关影响；follow：跟随客户端开关；off：强制关闭
// 节点出站拨号 IP 版本：开启 IPv6 时用 ipv4-prefer（先 IPv4，不通再 IPv6），关闭时用 dual。
// 只决定客户端连节点服务器用哪个协议栈，不影响最终出口。
// 不用 ipv6-prefer：它曾导致优选域名节点 TCP 通但 TLS / WS 握手被重置，且不回退 IPv4
const IPV6_MODE = "on";

// DNS 防泄漏：false 时海外域名一律走脚本里的海外 DoH（经代理出站），忽略订阅自带的 nameserver
const TRUST_SUB_NAMESERVER = false;

// 订阅配置清理：删除订阅里的 listeners / authentication / skip-auth-prefixes
// （其引用的策略组在本脚本重建后已不存在，会让内核报错，也可能把本机变成对局域网开放的代理）
const SANITIZE_SUB_CONFIG = true;

// 节点命名：true 时本地节点统一命名为"国旗 简称 原名"（如 🇭🇰 HK 联通优选），已有国旗 / 简称的保留并去重；
// 没有任何地区信息的节点（如"三网优选"）会在名称前加一个图标。家宽节点仅统一地区前缀并清理重复地区代码
const RENAME_NODES = true;

// ════════════════════════════════════════
// 三、静态表与通用函数（无需修改）
// ════════════════════════════════════════

// 节点名里的信息类关键词（剩余流量、到期时间、群链接、"防失联页 https://…"等），这类节点不进可选列表
const excludeFilter =
    "(?i)(https?://|失联|剩余|官网|套餐|流量|到期|过期|更新|刷新|订阅|重置|通知|本站|群|网址|客服|欢迎|加入|Expire|Traffic|Reset|(^|[^A-Za-z0-9])(\\d+(\\.\\d+)?\\s*(GB|TB)|\\d+\\s*Days?)([^A-Za-z0-9]|$))";

// 内核用 Go 正则，JS 侧不支持 (?i) 前缀，需转换
const toJsRegex = goStyleRegex =>
    new RegExp(goStyleRegex.replace(/^\(\?i\)/, ""), "i");

const excludeRe = toJsRegex(excludeFilter);

// 两位国家代码 → 国旗 emoji
const flagOf = code =>
    String.fromCodePoint(
        0x1f1e6 + code.charCodeAt(0) - 65,
        0x1f1e6 + code.charCodeAt(1) - 65
    );

// 地区表。name：两位国家代码；cn：中文名（用于地区组命名）；
// regex：内核 group filter 与 JS 侧共用同一串
const regions = [
    {
        name: "AE",
        cn: "阿联酋",
        regex: "(?i)(阿联酋|阿聯酋|迪拜|阿布扎比|🇦🇪|(^|[^A-Za-z])UAE([^A-Za-z]|$)|(^|[^A-Za-z])ARE([^A-Za-z]|$)|Emirates|Dubai)",
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
        name: "EE",
        cn: "爱沙尼亚",
        regex: "(?i)(爱沙尼亚|愛沙尼亞|塔林|🇪🇪|(^|[^A-Za-z])EE([^A-Za-z]|$)|(^|[^A-Za-z])EST([^A-Za-z]|$)|Estonia|Tallinn)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/ee.svg"
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
        regex: "(?i)(法国|法國|巴黎|🇫🇷|(^|[^A-Za-z])FR([^A-Za-z]|$)|France|Paris)",
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
        // 印度([^尼]|$) 只排除"印度尼西亚"；含独立 token IN 的节点名可能同时命中 ID 与 IN，各组 filter 相互独立
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
        name: "RO",
        cn: "罗马尼亚",
        regex: "(?i)(罗马尼亚|羅馬尼亞|布加勒斯特|🇷🇴|(^|[^A-Za-z])RO([^A-Za-z]|$)|(^|[^A-Za-z])ROU([^A-Za-z]|$)|Romania|Bucharest)",
        icon: "https://cdn.jsdmirror.com/gh/HatScripts/circle-flags@gh-pages/flags/ro.svg"
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

// 地区组显示名：普通组如 🇭🇰香港节点，家宽组如 🇭🇰香港家宽（仅用于策略组名）
regions.forEach(region => {
    region.label = flagOf(region.name) + region.cn + "节点";
    region.homeLabel = flagOf(region.name) + region.cn + "家宽";
});

// 应用组名单与图标；direct: true 的组默认选中"直连连接"
const apps = [
    { name: "AI", icon: "openai.png" },
    { name: "Apple", icon: "apple.png" },
    {
        name: "GitHub",
        icon: "https://gh-proxy.com/https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/04ProxySoft/github(1).png"
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

// 脚本生成的固定组名
const OWN_GROUPS = [
    PROXY_GROUP,
    AUTO_GROUP,
    MANUAL_GROUP,
    MANUAL_ENTRY,
    DIRECT_GROUP,
    TUNNEL_GROUP,
    FRONT_AUTO,
    HOME_AUTO,
    HOME_GROUP,
    ...apps.map(app => app.name)
];

// 内建策略名（RULES：DNS 连接按路由规则出站）
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

// 节点与策略组共享命名空间且节点名必须唯一：与组名 / 内建策略重名、或订阅内重名的节点会让内核启动报错，
// main 里会先行改名
const RESERVED_NAMES = new Set([
    ...OWN_GROUPS,
    ...regions.map(region => region.label),
    ...regions.map(region => region.homeLabel),
    ...BUILTIN_POLICIES
]);

// 部分客户端脚本引擎没有 console.warn，统一降级输出
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

// 家宽节点：OpenVPN 类型，或通过 dialer-proxy 依赖"隧道前置"的节点。
// 这类节点保持原名，不参与地区组 / 自动选择 / 手动选择，由"家宽自动""家宽出口"单独管理
const isHomeProxy = proxy =>
    !!proxy &&
    (proxy.type === "openvpn" ||
        proxy["dialer-proxy"] === TUNNEL_GROUP);

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

// 自然排序：名字中的连续数字段按数值比较（"HK 2" 排在 "HK 10" 之前）。
// 数字段与文本段错位时数字段在前；数值相同（"01" 与 "1"）时按文本比较，保证全序
const naturalCompare = (a, b) => {
    const split = s => String(s).match(/\d+|\D+/g) || [];
    const pa = split(a);
    const pb = split(b);
    const len = Math.min(pa.length, pb.length);

    for (let i = 0; i < len; i++) {
        if (pa[i] === pb[i]) continue;

        const numA = /^\d/.test(pa[i]);
        const numB = /^\d/.test(pb[i]);

        if (numA && numB) {
            const diff = Number(pa[i]) - Number(pb[i]);
            if (diff !== 0) return diff;
        } else if (numA !== numB) {
            return numA ? -1 : 1;
        }

        return pa[i] < pb[i] ? -1 : 1;
    }

    return pa.length - pb.length;
};

// ── 节点命名与地区识别 ──
// 命名格式："国旗 简称 原名"。识别顺序：①名字里已有的国旗；②去掉 []/()/【】内容后最靠前的地区关键词
// （避免括号里的域名误导判断）；③完整名字。
// 带有表中没有的国旗（如 🇨🇳）的节点、信息类节点保持原样。proxy-providers 的节点脚本不可见，无法改名
const CODE_ALIASES = {
    AE: ["UAE", "ARE"], AR: ["ARG"], AU: ["AUS"], BD: ["BGD"], BR: ["BRA"],
    CA: ["CAN"], CH: ["CHE"], DE: ["DEU"], EE: ["EST"], FI: ["FIN"], FR: [],
    GB: ["UK", "GBR"], HK: ["HKG"], ID: ["IDN"], IN: ["IND"],
    JP: ["JPN"], KR: ["KOR"], LV: ["LVA"], MY: ["MYS"], NL: ["NLD"],
    PH: ["PHL"], PL: ["POL"], RO: ["ROU"], RU: ["RUS"], SE: ["SWE"], SG: ["SGP"],
    TH: ["THA"], TR: ["TUR"], TW: ["TWN"], US: ["USA"], VN: ["VNM"]
};

const regionByCode = new Map(
    regions.map(region => [region.name, region])
);

// 地区代码别名表：两位代码、三字码（HKG / JPN / USA …）、UK / UAE 等都指向两位代码，
// 供 FRONT_APPEND_REGIONS 之类的参数使用（节点名里的识别由各地区的 regex 负责）
const regionCodeAlias = new Map();

regions.forEach(region => regionCodeAlias.set(region.name, region.name));
Object.keys(CODE_ALIASES).forEach(code => {
    CODE_ALIASES[code].forEach(alias => regionCodeAlias.set(alias, code));
});
const regionRegexes = regions.map(region => ({
    code: region.name,
    re: toJsRegex(region.regex)
}));

// 取名字里出现的全部国旗对应的两位代码（按出现顺序；不用带 u 标志的正则，兼容性更好）
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

const BRACKET_RE = /\[[^\]]*\]|［[^］]*］|【[^】]*】|\([^)]*\)|（[^）]*）/g;

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

// 机场三字码（IATA）→ 地区：优选工具常用机场码标注数据中心。只在名字里没有任何其它地区信息时作为识别依据，
// 名字里的机场码只用于识别，命名时去掉（见 formatNodeName）。FRA 按法兰克福（德国）算；与国家三字码撞车的 CAN / AUS / IND 不收录，仍按国家码识别；
// 只匹配大写形式，避免普通英文单词误判
const AIRPORT_REGION = {};

[
    ["US", "SJC LAX SEA SFO ORD DFW IAD EWR JFK ATL MIA DEN PDX PHX LAS SLC BOS IAH MSP DTW"],
    ["JP", "NRT HND KIX ITM NGO FUK CTS OKA"],
    ["SG", "SIN"],
    ["KR", "ICN GMP PUS"],
    ["TW", "TPE KHH"],
    ["DE", "FRA MUC BER DUS CGN"],
    ["EE", "TLL"],
    ["FR", "CDG ORY MRS LYS NCE"],
    ["GB", "LHR LGW EDI STN"],
    ["NL", "AMS"],
    ["CA", "YYZ YVR YUL"],
    ["AU", "SYD MEL BNE ADL"],
    ["IN", "BOM BLR MAA HYD CCU"],
    ["MY", "KUL"],
    ["TH", "BKK"],
    ["ID", "CGK"],
    ["PH", "MNL CEB"],
    ["VN", "SGN HAN"],
    ["AE", "DXB AUH"],
    ["TR", "IST SAW"],
    ["RU", "SVO DME LED"],
    ["BR", "GRU GIG"],
    ["AR", "EZE"],
    ["CH", "ZRH GVA"],
    ["SE", "ARN"],
    ["FI", "HEL"],
    ["PL", "WAW"],
    ["RO", "OTP"],
    ["LV", "RIX"],
    ["BD", "DAC"]
].forEach(([code, list]) => {
    list.split(" ").forEach(airport => {
        AIRPORT_REGION[airport] = code;
    });
});

const airportRegionOf = text => {
    const tokens = String(text).split(/[^A-Za-z0-9]+/);

    for (const token of tokens) {
        if (Object.prototype.hasOwnProperty.call(AIRPORT_REGION, token)) {
            return AIRPORT_REGION[token];
        }
    }

    return "";
};

// 地区 → 该地区的机场码列表（命名时按识别出的地区去掉对应机场码）
const AIRPORTS_BY_REGION = {};

Object.keys(AIRPORT_REGION).forEach(airport => {
    const region = AIRPORT_REGION[airport];

    if (!AIRPORTS_BY_REGION[region]) AIRPORTS_BY_REGION[region] = [];
    AIRPORTS_BY_REGION[region].push(airport);
});

const detectRegion = name => {
    const flags = flagCodesIn(name);

    for (const code of flags) {
        if (regionByCode.has(code)) return code;
    }

    // 带有表中没有的国旗：尊重原标注
    if (flags.length > 0) return "";

    return (
        earliestRegion(name.replace(BRACKET_RE, " ")) ||
        earliestRegion(name) ||
        airportRegionOf(name.replace(BRACKET_RE, " ")) ||
        airportRegionOf(name)
    );
};

// 分隔符：去掉国旗 / 简称 / 三字码后，它们前后的分隔符一并整理
const SEP_END_RE = /[\s\-_|·•,，、:：/.]+$/;
const SEP_START_RE = /^[\s\-_|·•,，、:：/.]+/;

// 两段文字之间原来夹着一个被去掉的词：左右分隔符合并成一个。
// 一侧没有文字（开头 / 结尾）时分隔符全部去掉；两侧都有分隔符时优先保留可见的（- _ | 等）
const joinAfterRemoval = (left, right) => {
    const ls = (SEP_END_RE.exec(left) || [""])[0];
    const rs = (SEP_START_RE.exec(right) || [""])[0];
    const lc = left.slice(0, left.length - ls.length);
    const rc = right.slice(rs.length);

    if (lc === "") return rc;
    if (rc === "") return lc;

    let sep = ls || rs;

    if (ls && rs) sep = ls.trim() ? ls : rs.trim() ? rs : ls;

    return lc + sep + rc;
};

// 从文字里去掉：国旗、国家简称（不分大小写）、机场码（只认大写）；
// 简称 / 机场码要求前面不是字母数字、后面不是字母（"家宽KR-27" 里的 KR 也算）
const removeRegionTokens = (text, flag, countryTokens, airportTokens) => {
    const ranges = [];

    if (flag) {
        let i = text.indexOf(flag);

        while (i !== -1) {
            ranges.push([i, i + flag.length]);
            i = text.indexOf(flag, i + flag.length);
        }
    }

    const collect = (tokens, ignoreCase) => {
        if (tokens.length === 0) return;

        const re = new RegExp(
            "(^|[^A-Za-z0-9])(" + tokens.join("|") + ")(?![A-Za-z])",
            ignoreCase ? "gi" : "g"
        );
        let m;

        while ((m = re.exec(text)) !== null) {
            const start = m.index + m[1].length;

            ranges.push([start, start + m[2].length]);
        }
    };

    collect(countryTokens, true);
    collect(airportTokens, false);

    if (ranges.length === 0) return text;

    ranges.sort((x, y) => x[0] - y[0]);

    // 合并重叠区间
    const merged = [];

    ranges.forEach(range => {
        const last = merged[merged.length - 1];

        if (last && range[0] <= last[1]) {
            last[1] = Math.max(last[1], range[1]);
        } else {
            merged.push([range[0], range[1]]);
        }
    });

    let result = text.slice(0, merged[0][0]);

    merged.forEach((range, index) => {
        const next = index + 1 < merged.length ? merged[index + 1][0] : text.length;

        result = joinAfterRemoval(result, text.slice(range[1], next));
    });

    return result;
};

// 命名："国旗 简称 原名"。原名里重复的国旗 / 简称 / 国家三字码 / 机场码只用于识别，去掉（连同前后分隔符）；
// 机场码去掉后名字里不剩任何文字（如只有 "SJC-01"）时保留机场码，避免不同节点名字全部变成一样
const formatNodeName = (name, code) => {
    const flag = flagOf(code);
    const countryTokens = [code, ...(CODE_ALIASES[code] || [])];
    const airportTokens = AIRPORTS_BY_REGION[code] || [];

    // 括号内容先换成占位符、清理完再还原，避免域名后缀（.nl / .us / .sg）被当成地区简称误删
    const bracketParts = [];
    const masked = name.replace(BRACKET_RE, part => {
        bracketParts.push(part);
        return "\uE000" + (bracketParts.length - 1) + "\uE001";
    });

    const clean = tokens =>
        removeRegionTokens(masked, flag, countryTokens, tokens)
            .replace(/\s+/g, " ")
            .replace(/^[\s\-_|·•,，、:：/.]+/, "")
            .replace(/[\s\-_|·•,，、:：/.]+$/, "")
            .trim();

    const keepAirport = clean([]);
    const dropAirport = clean(airportTokens);
    const hasText = text =>
        /[A-Za-z\u00C0-\u024F\u3040-\u30FF\u3400-\u9FFF\uAC00-\uD7AF]/.test(
            text.replace(/\uE000\d+\uE001/g, "")
        );

    const rest = (
        airportTokens.length > 0 && hasText(dropAirport)
            ? dropAirport
            : keepAirport
    ).replace(
        /\uE000(\d+)\uE001/g,
        (_, index) => bracketParts[Number(index)]
    );

    return rest ? flag + " " + code + " " + rest : flag + " " + code;
};

// 名字末尾的括号段（中英文小括号、中括号、全角方括号、【】，可连续多个）
const TRAILING_BRACKETS_RE =
    /^(.*?)(\s*(?:(?:\[[^\]]*\]|［[^］]*］|【[^】]*】|\([^)]*\)|（[^）]*）)\s*)+)$/;

// 在名字末尾括号段的前面插入序号文本；没有末尾括号（或整个名字就是括号）时加在名字最后
const withSerial = (name, serial) => {
    const m = TRAILING_BRACKETS_RE.exec(name);

    if (!m || m[1].trim() === "") return name + serial;

    return m[1].replace(/\s+$/, "") + serial + m[2];
};

// 名字是否已带序号：去掉末尾括号后，以数字结尾，且数字前面不是英文字母（IPv4、IPv6 里的 4、6 不算序号）
const hasSerial = name => {
    const m = TRAILING_BRACKETS_RE.exec(name);
    const core = m && m[1].trim() !== "" ? m[1] : name;

    return /(^|[^A-Za-z])\d+\s*$/.test(core);
};

// 无地区信息节点的名称前缀图标
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

// 节点解析 DNS 不得经代理 / 策略组出站（否则"需要节点才能解析节点"形成循环），去掉 # 后的目标名，只保留 k=v 参数
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

// 指向已重建规则集 / 内建 geo 的键会报错或触发额外下载，一律丢弃
const isDanglingKey = key => /^(rule-set|geosite|geoip):/i.test(key);

// 是否为纯域名（非 IP）
const isDomainName = value =>
    typeof value === "string" &&
    /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(value) &&
    !/^\d+(\.\d+){3}$/.test(value);

// 仅这三类协议有 client-fingerprint 字段
const FP_OK = ["vless", "vmess", "trojan"];

// provider 节点的指纹注入表达式（节点运行时才出现，只能用 override 表达式），条件须与 main 里本地节点的判定一致；
// 用 .["client-fingerprint"] 避免 yq / jq 把连字符误解析为减法
const FP_EXPR =
    '(select(.type == "trojan" or ((.type == "vless" or .type == "vmess") and (.tls == true or has("reality-opts")))) | select(has("client-fingerprint") | not) | .["client-fingerprint"]) = "chrome"';

// 规范化为表达式数组；类型非法返回 null（调用方原样保留该 provider，不注入）
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

// ── 前置节点导入（解析 IMPORT_LINKS）──

const safeDecode = text => {
    try {
        return decodeURIComponent(text);
    } catch (error) {
        return text;
    }
};

const truthyFlag = value =>
    value === "1" || String(value).toLowerCase() === "true";

// 合法服务器地址：IPv4、IPv6 或带点的英文域名（汉字说明、没写完整的文字不会被当成地址）
const isValidHost = host =>
    /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ||
    (host.indexOf(":") !== -1 && /^[0-9a-fA-F:.]+$/.test(host)) ||
    /^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(host);

// 解析 "host[:port]" / "[ipv6][:port]"；端口可能是 "443,5000-6000" 这类端口段（hysteria2），取第一个数字作端口
const parseHostPort = text => {
    const hp = String(text || "").trim();
    let m = /^\[([0-9a-fA-F:.]+)\](?::(\d[\d,\-]*))?$/.exec(hp);

    if (!m) m = /^([^:\s/[\]]+)(?::(\d[\d,\-]*))?$/.exec(hp);

    if (m && !isValidHost(m[1])) return null;

    if (m) {
        const spec = m[2] || "";

        return {
            host: m[1],
            port: spec ? parseInt(spec, 10) : 0,
            portSpec: spec
        };
    }

    // 没加方括号的纯 IPv6
    if (/^[0-9a-fA-F:]+$/.test(hp) && hp.indexOf(":") !== -1 && isValidHost(hp)) {
        return { host: hp, port: 0, portSpec: "" };
    }

    return null;
};

const parseQuery = qs => {
    const out = {};

    String(qs || "")
        .split("&")
        .forEach(pair => {
            if (!pair) return;

            const i = pair.indexOf("=");
            const key = i === -1 ? pair : pair.slice(0, i);
            const value = i === -1 ? "" : pair.slice(i + 1);

            out[safeDecode(key).toLowerCase()] = safeDecode(value);
        });

    return out;
};

// 传输层：支持 tcp / ws / httpupgrade / grpc，其余返回 false
const applyTransport = (proxy, q, network) => {
    if (network === "ws" || network === "httpupgrade") {
        const wsOpts = { path: q.path || "/" };
        const hostHeader = q.host || q.sni;

        if (hostHeader) wsOpts.headers = { Host: hostHeader };
        if (network === "httpupgrade") wsOpts["v2ray-http-upgrade"] = true;

        proxy.network = "ws";
        proxy["ws-opts"] = wsOpts;
        return true;
    }

    if (network === "grpc") {
        proxy.network = "grpc";
        proxy["grpc-opts"] = {
            "grpc-service-name": q.servicename || ""
        };
        return true;
    }

    if (network === "tcp" || network === "") {
        proxy.network = "tcp";
        return true;
    }

    return false;
};

// TLS 相关字段：sni / 证书校验 / 指纹 / alpn / ECH / reality
const applyTls = (proxy, q, isTrojan, security) => {
    const useTls = isTrojan
        ? security !== "none"
        : security === "tls" || security === "reality";

    if (!isTrojan) proxy.tls = useTls;
    if (!useTls) return;

    const sni = q.sni || q.peer || q.host || "";

    if (sni) {
        if (isTrojan) proxy.sni = sni;
        else proxy.servername = sni;
    }

    if (truthyFlag(q.insecure) || truthyFlag(q.allowinsecure)) {
        proxy["skip-cert-verify"] = true;
    }

    if (q.fp) proxy["client-fingerprint"] = q.fp;

    if (q.alpn) {
        const alpn = q.alpn
            .split(",")
            .map(item => item.trim())
            .filter(Boolean);

        if (alpn.length > 0) proxy.alpn = alpn;
    }

    // ech 参数形如 "cloudflare-ech.com+https://223.5.5.5/dns-query"，取 + 前面的 ECH 查询域名
    if (q.ech) {
        const queryName = q.ech.split("+")[0].trim();

        if (isDomainName(queryName)) {
            proxy["ech-opts"] = {
                enable: true,
                "query-server-name": queryName
            };
        }
    }

    if (security === "reality") {
        proxy["reality-opts"] = {
            "public-key": q.pbk || "",
            "short-id": q.sid || ""
        };
    }
};

// 分享链接：vless:// trojan:// hysteria2:// (hy2://)。参数全部取自链接本身
const parseShareLink = (scheme, rest) => {
    if (["vless", "trojan", "hysteria2", "hy2"].indexOf(scheme) === -1) {
        return { error: "暂不支持的协议 " + scheme + "://（目前支持 vless / trojan / hysteria2）" };
    }

    const hashIdx = rest.indexOf("#");
    const fragment =
        hashIdx === -1 ? "" : safeDecode(rest.slice(hashIdx + 1)).trim();
    const body = hashIdx === -1 ? rest : rest.slice(0, hashIdx);
    const qIdx = body.indexOf("?");
    const q = parseQuery(qIdx === -1 ? "" : body.slice(qIdx + 1));
    const auth = qIdx === -1 ? body : body.slice(0, qIdx);
    const at = auth.lastIndexOf("@");

    if (at === -1) return { error: "链接缺少 @（认证信息）" };

    const userinfo = safeDecode(auth.slice(0, at));
    const hp = parseHostPort(auth.slice(at + 1).replace(/\/+$/, ""));

    if (!hp) return { error: "无法解析服务器地址" };
    if (hp.port && (hp.port < 1 || hp.port > 65535)) {
        return { error: "端口超出范围" };
    }
    if (!userinfo) return { error: "链接缺少 uuid / 密码" };

    const name = fragment || "导入-" + hp.host;

    if (scheme === "vless") {
        const proxy = {
            name,
            type: "vless",
            server: hp.host,
            port: hp.port || 443,
            uuid: userinfo,
            udp: true
        };

        if (!applyTransport(proxy, q, (q.type || "tcp").toLowerCase())) {
            return { error: "暂不支持的传输方式 " + q.type };
        }

        applyTls(proxy, q, false, (q.security || "none").toLowerCase());

        if (q.flow) proxy.flow = q.flow;

        return { proxy };
    }

    if (scheme === "trojan") {
        const proxy = {
            name,
            type: "trojan",
            server: hp.host,
            port: hp.port || 443,
            password: userinfo,
            udp: true
        };

        if (!applyTransport(proxy, q, (q.type || "tcp").toLowerCase())) {
            return { error: "暂不支持的传输方式 " + q.type };
        }

        applyTls(proxy, q, true, (q.security || "tls").toLowerCase());

        return { proxy };
    }

    if (scheme === "hysteria2" || scheme === "hy2") {
        const proxy = {
            name,
            type: "hysteria2",
            server: hp.host,
            port: hp.port || 443,
            password: userinfo
        };

        // 端口段（如 443,5000-6000）或 mport 参数
        const portSpec = q.mport || (/[,-]/.test(hp.portSpec) ? hp.portSpec : "");

        if (portSpec) proxy.ports = portSpec;
        if (q.sni) proxy.sni = q.sni;

        if (truthyFlag(q.insecure) || truthyFlag(q.allowinsecure)) {
            proxy["skip-cert-verify"] = true;
        }

        if (q.alpn) {
            const alpn = q.alpn
                .split(",")
                .map(item => item.trim())
                .filter(Boolean);

            if (alpn.length > 0) proxy.alpn = alpn;
        }

        if (q.obfs) {
            proxy.obfs = q.obfs;
            if (q["obfs-password"]) proxy["obfs-password"] = q["obfs-password"];
        }

        return { proxy };
    }

    return { error: "暂不支持的协议 " + scheme + "://" };
};

// 裸 IP / 域名：只有地址和备注，其余参数借用订阅里的模板节点
const parseBareAddress = (line, template) => {
    const hashIdx = line.indexOf("#");
    const addr = (hashIdx === -1 ? line : line.slice(0, hashIdx)).trim();
    const remark =
        hashIdx === -1 ? "" : safeDecode(line.slice(hashIdx + 1)).trim();
    const hp = parseHostPort(addr);

    if (!hp) return { error: "无法识别为 IP / 域名" };
    if (hp.port && (hp.port < 1 || hp.port > 65535)) {
        return { error: "端口超出范围" };
    }
    if (!template) {
        return { error: "订阅里没有可借用的 ws+tls 节点，无法导入裸 IP / 域名" };
    }

    const copy = JSON.parse(JSON.stringify(template));

    copy.name =
        remark || "优选 " + hp.host + (hp.port ? ":" + hp.port : "");
    copy.server = hp.host;

    if (hp.port) copy.port = hp.port;

    return { proxy: copy };
};

// 模板节点所属的域名（servername / sni / ws Host），用来给模板去重
const importDomainOf = proxy => {
    const ws = isPlainObject(proxy["ws-opts"]) ? proxy["ws-opts"] : {};
    const headers = isPlainObject(ws.headers) ? ws.headers : {};

    return String(
        proxy.servername || proxy.sni || headers.Host || headers.host || ""
    ).toLowerCase();
};

// 在订阅节点里找模板：非家宽、ws 传输、带 TLS 的 vless（优先）或 trojan，同一个域名只留第一个。
// cloudflare-ech.com 是 ECH 查询名而不是节点域名，servername / Host 是它的节点不作模板。
// 返回模板数组：rotate 返回全部（按订阅顺序），first 只返回第一个
const pickImportTemplates = proxies => {
    const echNames = new Set(["cloudflare-ech.com"]);

    proxies.forEach(proxy => {
        const ech = proxy && isPlainObject(proxy["ech-opts"]) ? proxy["ech-opts"] : {};
        const queryName = ech["query-server-name"];

        if (typeof queryName === "string" && queryName) {
            echNames.add(queryName.toLowerCase());
        }
    });

    const candidates = proxies.filter(
        proxy =>
            !!proxy &&
            !isHomeProxy(proxy) &&
            proxy.network === "ws" &&
            (proxy.tls === true || proxy.type === "trojan") &&
            !excludeRe.test(proxy.name || "") &&
            !echNames.has(importDomainOf(proxy))
    );

    const vless = candidates.filter(
        proxy => proxy.type === "vless" && proxy.uuid
    );
    const pool =
        vless.length > 0
            ? vless
            : candidates.filter(
                  proxy => proxy.type === "trojan" && proxy.password
              );

    const seen = new Set();
    const templates = [];

    pool.forEach(proxy => {
        const key = importDomainOf(proxy);

        if (seen.has(key)) return;

        seen.add(key);
        templates.push(proxy);
    });

    return IMPORT_DOMAIN_MODE === "rotate" ? templates : templates.slice(0, 1);
};

// 追加前置节点时不取这些类型：UDP 协议不适合承载前置流量，direct / reject 不是真实节点
const FRONT_APPEND_SKIP_TYPES = [
    "direct",
    "reject",
    "hysteria",
    "hysteria2",
    "tuic",
    "wireguard",
    "openvpn"
];

// 节点去重用的指纹：类型 + 服务器 + 端口 + 域名（SNI / Host）
const nodeKeyOf = proxy =>
    [
        proxy.type,
        String(proxy.server || "").toLowerCase(),
        proxy.port,
        importDomainOf(proxy)
    ].join("|");

// 同一行里用逗号 / 分号（中英文都行）隔开多个节点也能拆开。为了不误伤备注和链接参数，
// 只有分隔符后面紧跟"协议://"，或紧跟"IPv4 / [IPv6] / 带点的域名（可带端口），再接 # 或分隔符或行尾"时才拆
const IMPORT_SPLIT_RE =
    /[,，；;]\s*(?=[a-z][a-z0-9+.-]*:\/\/|(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]+\]|(?:[a-z0-9-]+\.)+[a-z0-9-]+)(?::\d+)?(?:#|[,，；;]|$))/i;

const parseImportLinks = (text, templates) => {
    const proxies = [];
    const errors = [];
    // 裸 IP / 域名行的序号：按顺序轮流取模板（只在成功导入一行后前进）
    let bareIndex = 0;

    String(text || "")
        .split(/\r?\n/)
        .forEach(rawLine => {
            const trimmed = rawLine.trim();

            if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("#")) {
                return;
            }

            trimmed.split(IMPORT_SPLIT_RE).forEach(piece => {
                const line = piece.trim();

                if (!line) return;

                const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\/(.*)$/i.exec(line);
                const template =
                    !schemeMatch && templates.length > 0
                        ? templates[bareIndex % templates.length]
                        : null;
                const result = schemeMatch
                    ? parseShareLink(schemeMatch[1].toLowerCase(), schemeMatch[2])
                    : parseBareAddress(line, template);

                if (!schemeMatch && !result.error) bareIndex++;

                if (result.error) {
                    errors.push(result.error + "：" + line.slice(0, 60));
                } else {
                    proxies.push(result.proxy);
                }
            });
        });

    return { proxies, errors };
};

// 转义正则特殊字符（用于把节点名拼进 exclude-filter）
const regexQuote = text =>
    String(text).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// ════════════════════════════════════════
// 四、主函数
// ════════════════════════════════════════

function main(params) {
    if (!params || typeof params !== "object") params = {};
    if (!Array.isArray(params.proxies)) params.proxies = [];

    // 丢弃空名 / 非法节点（内核要求节点名非空且唯一）
    params.proxies = params.proxies.filter(
        proxy =>
            proxy &&
            typeof proxy.name === "string" &&
            proxy.name !== ""
    );

    // 剔除 UDP 家宽节点（见 FILTER_UDP_HOME）
    if (FILTER_UDP_HOME) {
        params.proxies = params.proxies.filter(
            proxy =>
                !(
                    proxy.type === "openvpn" &&
                    (proxy.udp === true ||
                        String(proxy.proto || "").toLowerCase() === "udp")
                )
        );
    }

    // ── 0. 导入前置节点 + 给家宽节点补 dialer-proxy ──
    // subOrder：订阅原节点（订阅原顺序，改名 / 排序之前）。模板、去重、追加前置备用都以它为准，
    // 也避免借用到导入节点自己
    const subOrder = params.proxies.slice();

    // 已有节点的指纹表（家宽节点不参与）：导入的节点与之重复时只引用已有的那个
    const knownNodes = new Map();

    subOrder.forEach(proxy => {
        if (isHomeProxy(proxy)) return;

        const key = nodeKeyOf(proxy);

        if (!knownNodes.has(key)) knownNodes.set(key, proxy);
    });

    // frontProxies：前置节点池（导入的 + 复用订阅里已有的 + 追加的），记录节点对象：
    // 后面节点会被改名 / 去重，按对象取最终名字最可靠；importedProxies：本次新注入的导入节点
    const frontProxies = [];
    const importedProxies = [];
    const importResult = parseImportLinks(
        IMPORT_LINKS,
        pickImportTemplates(subOrder)
    );

    importResult.errors.forEach(message => {
        warnLog("[Clash_rule.js] 导入节点失败（已跳过）：" + message);
    });

    importResult.proxies.forEach(proxy => {
        const key = nodeKeyOf(proxy);
        const exist = knownNodes.get(key);

        // 订阅里已有（或前面已导入过）同一个节点：不再新增，只把已有的放进前置池
        if (exist) {
            if (frontProxies.indexOf(exist) === -1) frontProxies.push(exist);
            return;
        }

        knownNodes.set(key, proxy);
        params.proxies.push(proxy);
        importedProxies.push(proxy);
        frontProxies.push(proxy);
    });

    // 追加订阅里排在前面的 N 个节点作为前置备用（订阅原顺序）
    const appendCount =
        FRONT_APPEND_COUNT === "auto"
            ? frontProxies.length > 0
                ? 0
                : 10
            : Math.max(0, parseInt(FRONT_APPEND_COUNT, 10) || 0);

    if (appendCount > 0) {
        // 地区筛选：用节点原名识别地区（与后面改名时的识别规则一致）
        const wantRegions = (
            Array.isArray(FRONT_APPEND_REGIONS)
                ? FRONT_APPEND_REGIONS.join(",")
                : String(FRONT_APPEND_REGIONS || "")
        )
            .split(/[\s,，;；]+/)
            .map(code => code.trim().toUpperCase())
            .filter(Boolean)
            // 三字码 / 别名统一换成两位代码（ALL 和认不出的代码保持原样）
            .map(code => regionCodeAlias.get(code) || code);
        const anyRegion =
            wantRegions.length === 0 || wantRegions.indexOf("ALL") !== -1;

        if (!anyRegion) {
            wantRegions
                .filter(code => !regionByCode.has(code))
                .forEach(code => {
                    warnLog(
                        "[Clash_rule.js] FRONT_APPEND_REGIONS 里的「" +
                            code +
                            "」不是支持的地区代码，已忽略。"
                    );
                });
        }

        const appended = subOrder
            .filter(
                proxy =>
                    !isHomeProxy(proxy) &&
                    FRONT_APPEND_SKIP_TYPES.indexOf(proxy.type) === -1 &&
                    !excludeRe.test(proxy.name) &&
                    frontProxies.indexOf(proxy) === -1 &&
                    (anyRegion ||
                        wantRegions.indexOf(detectRegion(proxy.name)) !== -1)
            )
            .slice(0, appendCount);

        appended.forEach(proxy => frontProxies.push(proxy));

        if (!anyRegion && appended.length === 0 && frontProxies.length === 0) {
            warnLog(
                "[Clash_rule.js] 没有找到符合 FRONT_APPEND_REGIONS 的订阅节点，「隧道前置」将回退为全部节点自动选择。"
            );
        }
    }

    // 家宽 OpenVPN 节点统一经"隧道前置"组拨号；订阅已指定的有效引用保留，失效引用在最终校验时回退
    params.proxies.forEach(proxy => {
        if (proxy.type === "openvpn" && !proxy["dialer-proxy"]) {
            proxy["dialer-proxy"] = TUNNEL_GROUP;
        }
    });

    // 记住面板手动选择与 fake-ip 缓存；订阅已设置的项以订阅为准
    params.profile = Object.assign(
        { "store-selected": true, "store-fake-ip": true },
        isPlainObject(params.profile) ? params.profile : {}
    );

    // 订阅是否使用 proxy-providers（决定地区组是全量还是按节点数筛选）
    const subHasProviders =
        Object.keys(params["proxy-providers"] || {}).length > 0;

    // 订阅里是否有家宽节点（有才建"隧道前置""家宽自动""家宽出口"）
    const hasHomeNodes = params.proxies.some(isHomeProxy);

    // ── 1. 基础选项 ──
    Object.assign(params, {
        "unified-delay": true,
        // 并发尝试多个 IP，取最快握手
        "tcp-concurrent": true,
        // 不匹配进程名，省掉每条连接的进程查找
        "find-process-mode": "off",
        // TCP 保活（秒）：平衡移动端电量与 NAT 会话活性
        "keep-alive-idle": 300,
        "keep-alive-interval": 30
    });

    // IPv6 由 IPV6_MODE 决定
    const ipv6Enabled =
        IPV6_MODE === "on"
            ? true
            : IPV6_MODE === "off"
              ? false
              : params.ipv6 === true;
    params.ipv6 = ipv6Enabled;
    // 节点出站 IP 版本，说明见 IPV6_MODE
    const defaultIpVersion = ipv6Enabled ? "ipv4-prefer" : "dual";

    // 内核已移除该字段，保留会启动报错
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

    // 已屏蔽 UDP 443 时 QUIC 嗅探无意义
    if (!BLOCK_QUIC) {
        sniffProtocols.QUIC = { ports: [443, 8443] };
    }

    params.sniffer = {
        enable: true,
        "force-dns-mapping": true,
        // 纯 IP 流量也嗅探：从 TLS SNI / HTTP Host 还原域名参与分流
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

    // ── 2. 节点处理：命名 → 去重 → 排序 → 出站 IP 版本 / 指纹 ──
    const proxyRegion = new Map();   // 节点对象 → 地区代码（仅本地节点）
    // 保留每个节点对象的原始名称。所有改名、编号和保留名处理完成后，再统一修复 dialer-proxy，
    // 避免只同步到中间名称，随后目标节点又因重名编号而失效。
    const originalProxyNames = new Map();

    params.proxies.forEach(proxy => {
        originalProxyNames.set(proxy, proxy.name);
    });

    if (RENAME_NODES) {
        params.proxies.forEach(proxy => {
            // 家宽节点：添加"国旗 简称"前缀，并清理原名里重复的地区代码（如 家宽JP-2 → 🇯🇵 JP 家宽-2）；
            // 识别不到地区、或已带国旗的不动
            if (isHomeProxy(proxy)) {
                if (flagCodesIn(proxy.name).length > 0) return;

                const homeCode = detectRegion(proxy.name);

                if (!homeCode) return;

                const homeName = formatNodeName(proxy.name, homeCode);

                proxy.name = homeName;
                return;
            }

            if (
                proxy.type === "direct" ||
                proxy.type === "reject" ||
                excludeRe.test(proxy.name)
            ) {
                return;
            }

            const code = detectRegion(proxy.name);

            if (!code) {
                // 带有表中没有的国旗：不加图标
                if (flagCodesIn(proxy.name).length > 0) return;

                // 已加过图标：不重复加
                if (hasNoRegionIcon(proxy.name)) return;

                const iconName =
                    pickNoRegionIcon(proxy.name) + " " + proxy.name;

                proxy.name = iconName;
                return;
            }

            const newName = formatNodeName(proxy.name, code);

            proxyRegion.set(proxy, code);

            if (newName !== proxy.name) {
                proxy.name = newName;
            }
        });
    }

    // 重名序号：改名之后名字完全相同、且名字末尾没有序号的节点，按出现顺序加 "-1"、"-2"……
    // （如两个"🇭🇰 HK 移动优选" → "🇭🇰 HK 移动优选-1"、"🇭🇰 HK 移动优选-2"）；
    // 名字末尾有括号时序号排在括号前面（"圣何塞 (147ms)" → "圣何塞-1 (147ms)"）；
    // 名字本身已带序号的保持原样，只出现一次的名字不加序号；序号避开已存在的同名节点
    const nameCount = new Map();

    params.proxies.forEach(proxy => {
        nameCount.set(proxy.name, (nameCount.get(proxy.name) || 0) + 1);
    });

    const takenNames = new Set(params.proxies.map(proxy => proxy.name));
    const serialNext = new Map();

    params.proxies.forEach(proxy => {
        const base = proxy.name;

        if (nameCount.get(base) < 2 || hasSerial(base)) return;

        let n = serialNext.get(base) || 0;
        let candidate;

        do {
            n++;
            candidate = withSerial(base, "-" + n);
        } while (takenNames.has(candidate) || RESERVED_NAMES.has(candidate));

        serialNext.set(base, n);
        takenNames.add(candidate);
        proxy.name = candidate;
    });

    // 去重 / 避开保留名（兜底：与组名重名、或名字末尾已带序号却仍然重复的节点）
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
                    : withSerial(name, "·" + suffix);
            } while (
                RESERVED_NAMES.has(candidate) ||
                usedProxyNames.has(candidate)
            );

            name = candidate;
            proxy.name = name;
        }

        usedProxyNames.add(name);
    });

    // 自然排序（在改名、去重之后）：各组用 include-all 取节点，组内顺序即此处顺序；
    // proxy-providers 的节点顺序由内核决定
    params.proxies.sort((a, b) => naturalCompare(a.name, b.name));

    // 前置节点的最终名字（改名 / 去重 / 排序之后），按自然排序展示
    const frontNames = frontProxies
        .map(proxy => proxy.name)
        .sort(naturalCompare);

    // 导入节点的去向（IMPORT_MODE）：
    // front 且订阅里有家宽节点（有"隧道前置"组）时，新导入的节点只给"隧道前置"引用，
    // 通过 exclude-filter 排除出其它组；没有家宽节点时前置组不存在，改为加入所有策略组，避免节点无处可用。
    // 复用的订阅节点和追加的订阅节点本来就是普通节点，不受影响
    const frontOnly =
        IMPORT_MODE !== "all" && hasHomeNodes && importedProxies.length > 0;

    if (IMPORT_MODE !== "all" && !hasHomeNodes && importedProxies.length > 0) {
        warnLog(
            "[Clash_rule.js] 订阅里没有家宽节点，没有「隧道前置」组，导入的节点已改为加入所有策略组。"
        );
    }

    if (frontOnly) {
        importedProxies
            .filter(proxy => proxy.type === "hysteria2")
            .forEach(proxy => {
                warnLog(
                    "[Clash_rule.js] 导入的 hysteria2 节点「" +
                        proxy.name +
                        "」是 UDP 协议，不适合作前置节点，建议 IMPORT_MODE 改为 all 当普通节点用。"
                );
            });
    }

    const frontOnlyProxies = new Set(frontOnly ? importedProxies : []);
    const frontOnlyNames = frontOnly
        ? importedProxies.map(proxy => proxy.name)
        : [];

    // 各 include-all 组统一使用的排除过滤：信息类节点 + 只给前置用的导入节点（按名字精确匹配）
    const groupExcludeFilter =
        frontOnlyNames.length > 0
            ? excludeFilter +
              "|^(?:" +
              frontOnlyNames.map(regexQuote).join("|") +
              ")$"
            : excludeFilter;

    // 本地节点：补出站 IP 版本与 TLS 指纹（不覆盖订阅已有取值；家宽节点保持原样）
    params.proxies.forEach(proxy => {
        if (isHomeProxy(proxy)) return;

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

    // provider 节点：健康检查 + 出站 IP 版本 + 指纹（脚本不可见节点，只能用 override 表达式）
    Object.entries(params["proxy-providers"] || {}).forEach(
        ([name, provider]) => {
            if (!provider || typeof provider !== "object") {
                return;
            }

            // 组的 url 健康检查只测 proxies 字段成员，provider 节点须靠自身 health-check 产出延迟，
            // 否则地区组拿不到延迟。enable 强制开启，其余项以订阅为准
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
                    timeout: 8000,
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

            // 保留上游表达式顺序；指纹表达式最多出现一次（订阅每次刷新都会重跑本段）
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
    // direct / reject 类型、家宽节点与只给前置用的导入节点不进任何普通可选组
    const allProxies = params.proxies.filter(
        proxy =>
            proxy.type !== "direct" &&
            proxy.type !== "reject" &&
            !isHomeProxy(proxy) &&
            !frontOnlyProxies.has(proxy)
    );

    // 本地订阅且已统一命名时，地区组按"国旗 简称"前缀精确匹配，
    // 避免括号里的域名把节点拉进别的地区组
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

    // provider 订阅时脚本看不到节点，保留全部地区组
    const activeRegions = subHasProviders ? regions : matchedRegions;
    const hasActiveRegions = activeRegions.length > 0;
    const regionLabels = activeRegions.map(region => region.label);

    // 家宽地区统计：使用改名、重名处理后的最终节点名，按实际家宽节点建地区测速组。
    // 只有一个家宽节点的地区也建组；识别不到地区的节点仍由全局“家宽自动 / 家宽出口”管理。
    const homeNodesByRegion = new Map();

    if (hasHomeNodes) {
        params.proxies.forEach(proxy => {
            if (!isHomeProxy(proxy)) return;

            const code = detectRegion(proxy.name);

            if (!code) return;
            if (!homeNodesByRegion.has(code)) homeNodesByRegion.set(code, []);
            homeNodesByRegion.get(code).push(proxy.name);
        });
    }

    const activeHomeRegions = regions.filter(region =>
        homeNodesByRegion.has(region.name)
    );
    const homeRegionLabels = activeHomeRegions.map(
        region => region.homeLabel
    );

    // ── 4. DNS ──
    // 订阅 DNS 里指向已重建策略组的 "#组名" 后缀会让内核报错，需清洗；
    // 无法沿用的字段一律丢弃，以脚本配置为准

    // 实际会建组的普通 / 家宽地区组名
    const REGION_NAMES = new Set([...regionLabels, ...homeRegionLabels]);

    // 所有本地节点名都是合法的 "#节点名" 引用，包括家宽和只给前置使用的导入节点；
    // provider 节点因脚本不可见而不在此集合中。
    const PROXY_NAMES = new Set(
        params.proxies.map(proxy => proxy && proxy.name).filter(Boolean)
    );

    // DNS 只能引用本次实际创建的固定组，不能仅凭 OWN_GROUPS 中的潜在组名放行。
    // 例如没有家宽节点时不会创建“家宽出口”，有前置池时才会创建“前置自动”。
    const ACTIVE_OWN_GROUPS = new Set([
        PROXY_GROUP,
        AUTO_GROUP,
        MANUAL_GROUP,
        MANUAL_ENTRY,
        DIRECT_GROUP,
        ...apps.map(app => app.name)
    ]);

    if (hasHomeNodes) {
        ACTIVE_OWN_GROUPS.add(TUNNEL_GROUP);
        ACTIVE_OWN_GROUPS.add(HOME_AUTO);
        ACTIVE_OWN_GROUPS.add(HOME_GROUP);

        if (frontNames.length > 0) ACTIVE_OWN_GROUPS.add(FRONT_AUTO);
    }

    // 校验 DNS 条目 "#目标"：合法则保留，指向已不存在的对象则剥掉并补 #RULES
    const refValid = ref =>
        BUILTIN_POLICIES.has(ref) ||
        ACTIVE_OWN_GROUPS.has(ref) ||
        REGION_NAMES.has(ref) ||
        PROXY_NAMES.has(ref);

    // # 后按 "&" 分段：含 "=" 的是参数（h3= / ecs= 等）原样保留，裸段是目标名需校验；
    // 无有效目标时补 #RULES 交给路由，避免剥成裸 URL 直连（会招致污染与泄漏）
    const stripDanglingRef = entry => {
        const s = String(entry);
        const hash = s.indexOf("#");

        if (hash === -1) return s;

        const rawParts = s
            .slice(hash + 1)
            .split("&")
            .map(part => part.trim())
            .filter(Boolean);
        const hasValidTarget = rawParts.some(
            part => !part.includes("=") && refValid(part)
        );
        const parts = rawParts.filter(
            part => part.includes("=") || refValid(part)
        );

        if (hasValidTarget) {
            return s.slice(0, hash) + "#" + parts.join("&");
        }

        // 即使还保留 h3= / ecs= 等参数，也必须补上有效出站目标，不能留下无目标 DNS 条目。
        const options = parts.filter(part => part.includes("="));

        return s.slice(0, hash) + "#" + ["RULES", ...options].join("&");
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

        // fake-ip-filter 仅在缺省 / blacklist 模式下继承（whitelist / rule 语义相反）
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

        // nameserver-policy 逐键清洗：通吃键会架空分流、指向规则集 / geo 的键会报错，均丢弃；值清洗悬空引用
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

        // proxy-server-nameserver-policy：rule-set / geosite / geoip 键丢弃，其余保留
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

        // 节点域名解析：订阅显式设置了 proxy-server-nameserver 就独占使用（连同其 policy）；
        // 未设置（或清洗后为空）则用 PROXY_SERVER_DNS。不从订阅的 nameserver / fallback 迁移：
        // 那是普通域名解析用的，常含海外或经代理的 DNS，拿来解析节点域名可能循环或被污染
        const subPSNClean = [
            ...new Set(subPSN.map(stripProxyRefs).filter(Boolean))
        ];
        const psnExplicit = subPSNClean.length > 0;

        return {
            subDNS,
            subNS,
            subPolicy,
            subFilter,
            proxyServerNameserver: psnExplicit
                ? subPSNClean
                : [...PROXY_SERVER_DNS],
            proxyServerNameserverPolicy: psnExplicit
                ? stripProxyRefsPolicy(subPSNPolicy)
                : undefined
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

    // DNS 层 IPv6 与全局 IPv6 开关一致
    const dnsIPv6 = ipv6Enabled;

    // 自定义域名的 DNS：代理域名用海外 DoH（经代理出站），直连域名用国内 DoH
    const customDnsPolicy = {};

    cleanDomains(CUSTOM_PROXY).forEach(domain => {
        customDnsPolicy["+." + domain] = [...OVERSEAS_DNS_DOH];
    });

    cleanDomains(CUSTOM_DIRECT).forEach(domain => {
        customDnsPolicy["+." + domain] = [...CN_DNS_DOH];
    });

    // 节点自身依赖的域名（ECH 查询名、SNI / servername、WS / XHTTP Host）：要在代理就绪前解析，
    // 走国内 DoH，避免"需要节点才能解析节点"的循环
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
        // 固定回环 + 非特权端口：避免订阅常见的 0.0.0.0:53 被系统 DNS 占用而启动失败；
        // 要给局域网设备当 DNS 用时改这一行，并自行确认端口与防火墙
        listen: "127.0.0.1:1053",
        ipv6: dnsIPv6,
        "prefer-h3": PREFER_H3,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        // IPv6 fake-ip 段（仅 DNS 启用 IPv6 时输出）
        ...(dnsIPv6
            ? { "fake-ip-range6": "fdfe:dcba:9876::/64" }
            : {}),
        "cache-algorithm": "arc",
        "fake-ip-filter-mode": "blacklist",
        // DNS 出站按路由规则走：#RULES 才能生效，海外 DoH 经代理、国内 DoH 直连，是防泄漏的关键
        "respect-rules": true,
        // 保留订阅自带的 hosts
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
        // 需要真实 IP 的域名：局域网、NTP、连通性探测、游戏平台（对时拿到假地址会失败，连带影响 TLS 校验），
        // 另含 STUN 通配与脚本规则集兜底
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
                "+.stun.*",
                "+.stun.*.*",
                "+.stun.*.*.*",
                "+.stun.*.*.*.*",
                "rule-set:cn-domain",
                "rule-set:private-domain",
                "rule-set:fakeip-filter",
                ...subFilter
            ])
        ],
        // 引导 DNS：只解析其它 DoH 服务器的域名；明文 IP 最快且不依赖证书校验
        "default-nameserver": [...CN_DNS_PLAIN],
        // 节点域名解析：订阅显式设置则独占其值，否则用 PROXY_SERVER_DNS
        "proxy-server-nameserver": proxyServerNameserver,
        ...(proxyServerNameserverPolicy &&
        Object.keys(proxyServerNameserverPolicy).length > 0
            ? {
                  "proxy-server-nameserver-policy":
                      proxyServerNameserverPolicy
              }
            : {}),
        // 海外域名：默认用海外 DoH，#RULES 按路由规则出站，查询不经本地运营商；
        // TRUST_SUB_NAMESERVER=true 时改用订阅自带的 nameserver
        nameserver:
            TRUST_SUB_NAMESERVER && subNS.length > 0
                ? [...new Set(subNS)]
                : [...OVERSEAS_DNS_DOH],
        // DIRECT 命中且未被 policy 覆盖的域名（冷门国内站点）用国内明文 DNS：
        // 只是国内域名，隐私影响小，且比 DoH 首次解析更快
        "direct-nameserver": [...CN_DNS_PLAIN],
        // DIRECT 命中的域名先走 nameserver-policy，未覆盖才落到 direct-nameserver
        "direct-nameserver-follow-policy": true,
        // 顺序即优先级：自定义域名与节点域名必须排在 rule-set:cn-domain 之前，
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
    // MetaCubeX 官方拆分库，全 mrs 格式
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

    // 其它来源的规则集（666OS / AWAvenue / wwqgtxx）：自行指定地址、行为、格式与缓存文件名
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

    // BT：公共 tracker + PT 站点域名（仅 BT_DIRECT 开启时创建）
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

    // 社区维护的 fake-ip 豁免清单，供 dns.fake-ip-filter 引用
    params["rule-providers"]["fakeip-filter"] = extraProvider(
        RS_FAKEIP_FILTER,
        "domain",
        "mrs",
        "fakeip-filter.mrs"
    );

    // 可选规则集：开关关闭则不创建，规则段里也不生成对应规则
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

    // 节点选择：唯一顶层入口。顺序：自动选择 → 各地区组 → 手动选择 → 家宽出口 → 直连连接
    groups.push({
        name: PROXY_GROUP,
        type: "select",
        icon: "https://cdn.jsdmirror.com/gh/Koolson/Qure@63be653774a6a83cd8e475a7b65f1ed68b9a0093/IconSet/Color/Proxy.png",
        proxies: [
            AUTO_GROUP,
            ...regionLabels,
            MANUAL_ENTRY,
            ...(hasHomeNodes ? [HOME_GROUP] : []),
            DIRECT_GROUP
        ]
    });

    // 自动选择：不分国家，全部可用节点里选延迟最低的（隐藏，只作为"节点选择"的成员显示）
    groups.push({
        name: AUTO_GROUP,
        type: "url-test",
        hidden: true,
        icon: "https://cdn.jsdmirror.com/gh/Koolson/Qure@63be653774a6a83cd8e475a7b65f1ed68b9a0093/IconSet/Color/Auto.png",
        "include-all": true,
        "exclude-type": NODE_EXCLUDE_TYPE,
        "exclude-filter": groupExcludeFilter,
        "empty-fallback": "REJECT",
        url: TEST_URL_PROXY,
        interval: AUTO_TEST_INTERVAL,
        tolerance: AUTO_TEST_TOLERANCE,
        lazy: true,
        timeout: 8000,
        "max-failed-times": 5,
        "expected-status": 204
    });

    // 手动选择：收全部普通节点（排除 direct / reject / 家宽 与信息类节点）
    groups.push({
        name: MANUAL_GROUP,
        type: "select",
        icon: "https://cdn.jsdmirror.com/gh/Koolson/Qure@63be653774a6a83cd8e475a7b65f1ed68b9a0093/IconSet/Color/Static.png",
        "include-all": true,
        "exclude-type": NODE_EXCLUDE_TYPE,
        "exclude-filter": groupExcludeFilter,
        "empty-fallback": "REJECT"
    });

    // 手动选择入口：隐藏，只在"节点选择"里显示为带图标的卡片，指向"手动选择"
    groups.push({
        name: MANUAL_ENTRY,
        type: "select",
        hidden: true,
        icon: "https://cdn.jsdmirror.com/gh/Koolson/Qure@63be653774a6a83cd8e475a7b65f1ed68b9a0093/IconSet/Color/Static.png",
        proxies: [MANUAL_GROUP]
    });

    // 直连组：隐藏，仅供内部选择引用，成员是内建 DIRECT
    groups.push({
        name: DIRECT_GROUP,
        type: "select",
        hidden: true,
        icon: "https://cdn.jsdmirror.com/gh/Koolson/Qure@63be653774a6a83cd8e475a7b65f1ed68b9a0093/IconSet/Color/Direct.png",
        proxies: ["DIRECT"]
    });

    // 家宽相关组（仅订阅里存在家宽节点时创建）
    if (hasHomeNodes) {
        // 隧道前置：家宽 OpenVPN 节点通过 dialer-proxy 经此组拨号（链路：本机 → 前置节点 → 家宽节点）。
        // 有导入的前置节点时：可见的 select 组，第一个选项「前置自动」，后面是各前置节点，可手动指定；
        // 没有导入节点时：回退为全部非家宽普通节点自动选延迟最低（必须排除 openvpn，否则会依赖自己形成循环）
        if (frontNames.length > 0) {
            groups.push({
                name: FRONT_AUTO,
                type: "url-test",
                hidden: true,
                proxies: [...frontNames],
                "empty-fallback": "REJECT",
                url: TEST_URL_PROXY,
                interval: AUTO_TEST_INTERVAL,
                tolerance: AUTO_TEST_TOLERANCE,
                lazy: true,
                timeout: 8000,
                "max-failed-times": 5,
                "expected-status": 204
            });

            groups.push({
                name: TUNNEL_GROUP,
                type: "select",
                icon: "https://cdn.jsdmirror.com/gh/Koolson/Qure@master/IconSet/Color/SSID.png",
                proxies: [FRONT_AUTO, ...frontNames]
            });
        } else {
            groups.push({
                name: TUNNEL_GROUP,
                type: "url-test",
                hidden: true,
                "include-all": true,
                "exclude-type": NODE_EXCLUDE_TYPE,
                "exclude-filter": groupExcludeFilter,
                "empty-fallback": "REJECT",
                url: TEST_URL_PROXY,
                interval: 300,
                tolerance: AUTO_TEST_TOLERANCE,
                lazy: true,
                timeout: 8000,
                "max-failed-times": 5,
                "expected-status": 204
            });
        }

        // 家宽地区测速组：只引用该地区的实际家宽节点，独立于普通机场地区组。
        // 与全局“家宽自动”共用测速参数；地区组内只比较该地区家宽节点的链路延迟。
        activeHomeRegions.forEach(region => {
            groups.push({
                name: region.homeLabel,
                type: "url-test",
                hidden: true,
                icon: region.icon,
                proxies: [...homeNodesByRegion.get(region.name)],
                "empty-fallback": "REJECT",
                url: TEST_URL_PROXY,
                interval: HOME_TEST_INTERVAL,
                tolerance: HOME_TEST_TOLERANCE,
                lazy: true,
                timeout: 8000,
                "max-failed-times": 5,
                "expected-status": 204
            });
        });

        // 家宽自动：在全部家宽节点里自动选延迟最低的（隐藏，只作为"家宽出口"的成员）
        groups.push({
            name: HOME_AUTO,
            type: "url-test",
            hidden: true,
            "include-all": true,
            filter: HOME_FILTER,
            "empty-fallback": "REJECT",
            url: TEST_URL_PROXY,
            interval: HOME_TEST_INTERVAL,
            tolerance: HOME_TEST_TOLERANCE,
            lazy: true,
            timeout: 8000,
            "max-failed-times": 5,
            "expected-status": 204
        });

        // 家宽出口：默认"家宽自动"，也可选择地区测速组或手动指定某个家宽节点（落地）
        groups.push({
            name: HOME_GROUP,
            type: "select",
            icon: "https://cdn.jsdmirror.com/gh/Koolson/Qure@master/IconSet/Color/Back.png",
            proxies: [HOME_AUTO, ...homeRegionLabels],
            "include-all": true,
            filter: HOME_FILTER,
            "empty-fallback": "REJECT"
        });
    }

    // 应用组：默认选中"节点选择"；direct 组（Microsoft）把"直连连接"排第一，默认直连
    const homeEntry = hasHomeNodes ? [HOME_GROUP] : [];
    const appProxiesList = [
        PROXY_GROUP,
        DIRECT_GROUP,
        ...homeEntry,
        ...regionLabels
    ];
    const appProxiesDirectFirst = [
        DIRECT_GROUP,
        PROXY_GROUP,
        ...homeEntry,
        ...regionLabels
    ];

    // proxies 给出切换目标，include-all 再加入全部普通节点，两者缺一不可
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
            "exclude-type": NODE_EXCLUDE_TYPE,
            "exclude-filter": groupExcludeFilter
        });
    });

    // 地区测速组（全隐藏）：本地订阅且已统一命名时按"国旗 简称"前缀精确匹配，否则用地区正则
    activeRegions.forEach(region => {
        groups.push({
            name: region.label,
            type: "url-test",
            hidden: true,
            icon: region.icon,
            "include-all": true,
            "exclude-type": NODE_EXCLUDE_TYPE,
            filter: anchoredGroups
                ? "(?i)^" + flagOf(region.name) + " " + region.name + "( |$)"
                : region.regex,
            "exclude-filter": groupExcludeFilter,
            // provider 订阅下可能一个节点都匹配不上，用 REJECT 兜底
            "empty-fallback": "REJECT",
            url: TEST_URL_PROXY,
            interval: AUTO_TEST_INTERVAL,
            tolerance: AUTO_TEST_TOLERANCE,
            lazy: true,
            timeout: 8000,
            "max-failed-times": 5,
            "expected-status": 204
        });
    });

    // 本地订阅下全部节点被 excludeFilter 过滤时，"手动选择"将为空并回落 REJECT（静默断网），留一条日志提示；
    // provider 订阅的节点脚本不可见，无法检查
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

    // 最终校验链式拨号引用。此时节点改名、重名编号、保留名处理和策略组重建均已完成。
    // 有效引用一律保持不变；旧节点名只有一个最终目标时同步改名，存在歧义时不猜测目标。
    const finalNamesByOriginalName = new Map();

    params.proxies.forEach(proxy => {
        const originalName = originalProxyNames.get(proxy);

        if (!originalName) return;
        if (!finalNamesByOriginalName.has(originalName)) {
            finalNamesByOriginalName.set(originalName, []);
        }

        finalNamesByOriginalName.get(originalName).push(proxy.name);
    });

    const dialerTargets = new Set([
        ...params.proxies.map(proxy => proxy.name),
        ...groups.map(group => group.name),
        ...BUILTIN_POLICIES
    ]);

    params.proxies.forEach(proxy => {
        const dialer = proxy["dialer-proxy"];

        const selfDial = dialer === proxy.name;

        if (
            typeof dialer !== "string" ||
            !dialer ||
            (!selfDial && dialerTargets.has(dialer))
        ) {
            return;
        }

        const renamedTargets = finalNamesByOriginalName.get(dialer) || [];

        if (
            renamedTargets.length === 1 &&
            renamedTargets[0] !== proxy.name
        ) {
            proxy["dialer-proxy"] = renamedTargets[0];
            warnLog(
                "[Clash_rule.js] 节点「" +
                    proxy.name +
                    "」的 dialer-proxy 目标已同步改名：「" +
                    dialer +
                    "」→「" +
                    renamedTargets[0] +
                    "」。"
            );
            return;
        }

        if (isHomeProxy(proxy)) {
            proxy["dialer-proxy"] = TUNNEL_GROUP;
            warnLog(
                "[Clash_rule.js] 家宽节点「" +
                    proxy.name +
                    "」的 dialer-proxy 目标「" +
                    dialer +
                    "」不存在或存在歧义，已回退为「" +
                    TUNNEL_GROUP +
                    "」。"
            );
            return;
        }

        // 非家宽节点不自动回退 DIRECT，避免本应走链式代理的流量意外直连。
        warnLog(
            "[Clash_rule.js] 节点「" +
                proxy.name +
                "」的 dialer-proxy 目标「" +
                dialer +
                "」不存在或存在歧义；为避免意外直连未自动修改，请检查订阅配置。"
        );
    });

    // ── 7. 规则 ──
    // 自定义域名规则
    const buildCustomRules = (list, policy) =>
        cleanDomains(list).map(
            domain => `DOMAIN-SUFFIX,${domain},${policy}`
        );

    // 自上而下先命中先决定，分五层：
    //   1. 私网 / 广告 / 追踪
    //   2. 传输层（NTP、QUIC / STUN 阻断、BT 直连），须排在应用分流前
    //   3. 自定义域名（优先于所有规则集）
    //   4. 应用分流（下载站直连排在通用代理域名之前）
    //   5. 国内直连 → MATCH 兜底
    // cn-domain 排在 Google / Apple / Microsoft 之后，避免其国内 CDN 域名被直连截胡
    params.rules = [
        "RULE-SET,private-domain,DIRECT",
        "RULE-SET,private-ip,DIRECT,no-resolve",
        "RULE-SET,ads-domain,REJECT",
        ...(BLOCK_TRACKING ? ["RULE-SET,tracking-domain,REJECT"] : []),
        ...(BLOCK_AWAVENUE ? ["RULE-SET,awavenue-ads,REJECT"] : []),
        // NTP 直连：很多节点丢弃 UDP 123，时间偏差会连带导致全局 TLS 校验失败
        "AND,((DST-PORT,123),(NETWORK,UDP)),DIRECT",
        ...(BLOCK_QUIC
            ? ["AND,((DST-PORT,443),(NETWORK,UDP)),REJECT"]
            : []),
        // STUN：3478 / 3479 标准端口，19302-19309 为 Google STUN
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

        // 自定义域名：直连在前、代理在后，同一域名同时出现时以直连为准
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
        // no-resolve：避免未收录站点在进入 MATCH 前被海外 nameserver 解析而引入延迟
        "RULE-SET,cn-ip,DIRECT,no-resolve",

        `MATCH,${PROXY_GROUP}`
    ];

    return params;
}

if (typeof module !== "undefined") {
    module.exports = main;
    module.exports.main = main;
}
