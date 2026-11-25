/**
 * Clash_rule_v6.5_Auto.js → Sing-Box 覆写脚本（核心分组 / 分流版）
 *
 * 用法：CFLink → 脚本覆写 → 新建脚本 → 类型选 Sing-Box → 粘贴本文件 → 保存，
 *       导出格式选「Sing-Box 配置（SFA 导入）」时选中它。
 *
 * 保留：节点选择 / 自动选择 / 手动选择 / 直连连接、地区测速组、应用策略组、
 *       广告与私网、QUIC/STUN、BT、常用应用、国内直连、兜底分流。
 * 去掉：OpenVPN、节点改名/过滤、proxy-providers、fake-ip/DNS、ECH、
 *       dialer-proxy、指纹注入、订阅清理等 mihomo 专属功能。
 *
 * 重要：分组是写进 Sing-Box 配置的 selector / urltest；SFA 的图形界面是否
 *       像 FlClash 一样展示分组取决于客户端版本。规则本身会按这些 tag 分流。
 */

const PROXY_GROUP = "节点选择";
const AUTO_GROUP = "⚡自动选择";
const MANUAL_GROUP = "手动选择";
const DIRECT_GROUP = "🏠直连连接";

const TEST_URL = "https://www.gstatic.com/generate_204";
const REGION_MIN_NODES = 2;        // 同地区至少几个节点才建地区组
const BLOCK_QUIC = true;           // UDP 443 拒绝（迫使浏览器走 TCP）
const BLOCK_STUN = true;           // STUN 端口拒绝（WebRTC 防泄漏）
const BT_DIRECT = true;            // BT tracker / PT 域名直连
const DOWNLOAD_VIA_DIRECT = true;  // 规则集下载直连；false 则走「节点选择」

// jsDelivr 上的 Sing-Box 规则集（.srs 二进制格式，不是 mihomo 的 .mrs）
const RULE_BASE = "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/";
const IP_BASE = "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/";
const HTTP_CLIENT_TAG = "cflink-ruleset-download";

const CUSTOM_PROXY = ["bilibili.tv", "biliintl.com", "bilicdn1.com"];
const CUSTOM_DIRECT = [".cn"];

// 应用组：组名 → Sing-Box geosite 规则集（对应 FlClash 里的应用分组）
const APP_RULES = [
    ["YouTube", ["youtube"]],
    ["Twitch", ["twitch"]],
    ["X", ["twitter"]],
    ["TikTok", ["tiktok"]],
    ["Telegram", ["telegram"]],
    ["AI", ["category-ai-!cn"]],
    ["GitHub", ["github"]],
    ["TV", ["netflix", "disney", "primevideo", "hbo", "apple-tvplus"]],
    ["Spotify", ["spotify"]],
    ["Google", ["google"]],
    ["Apple", ["apple"]],
    ["Microsoft", ["microsoft"]]
];

const APP_GROUP_NAMES = APP_RULES.map(item => item[0]);

// 地区表：代码 / 中文名 / 匹配节点 tag 的正则（只用于建地区组，不改节点名）
const REGIONS = [
    ["HK", "香港", /香港|🇭🇰|\bHK\b|\bHKG\b|Hong ?Kong/i],
    ["TW", "台湾", /台湾|台灣|台北|新北|🇹🇼|\bTW\b|\bTWN\b|Taiwan/i],
    ["JP", "日本", /日本|东京|東京|大阪|🇯🇵|\bJP\b|\bJPN\b|Japan/i],
    ["SG", "新加坡", /新加坡|狮城|獅城|🇸🇬|\bSG\b|\bSGP\b|Singapore/i],
    ["US", "美国", /美国|美國|洛杉矶|洛杉磯|圣何塞|聖何塞|硅谷|矽谷|西雅图|西雅圖|纽约|紐約|🇺🇸|\bUS\b|\bUSA\b|United[ -]?States/i],
    ["KR", "韩国", /韩国|韓國|南韩|南韓|首尔|首爾|🇰🇷|\bKR\b|\bKOR\b|Korea/i],
    ["GB", "英国", /英国|英國|伦敦|倫敦|🇬🇧|\bUK\b|\bGB\b|\bGBR\b|United[ -]?Kingdom|England|London/i],
    ["DE", "德国", /德国|德國|法兰克福|法蘭克福|🇩🇪|\bDE\b|\bDEU\b|Germany|Frankfurt/i],
    ["FR", "法国", /法国|法國|巴黎|🇫🇷|\bFR\b|France|Paris/i],
    ["NL", "荷兰", /荷兰|荷蘭|阿姆斯特丹|🇳🇱|\bNL\b|\bNLD\b|Netherlands|Amsterdam/i],
    ["CA", "加拿大", /加拿大|多伦多|多倫多|温哥华|溫哥華|🇨🇦|\bCA\b|\bCAN\b|Canada|Toronto|Vancouver/i],
    ["AU", "澳大利亚", /澳大利亚|澳大利亞|澳洲|悉尼|墨尔本|墨爾本|🇦🇺|\bAU\b|\bAUS\b|Australia|Sydney|Melbourne/i],
    ["IN", "印度", /印度([^尼]|$)|新德里|孟买|孟買|班加罗尔|班加羅爾|🇮🇳|\bIN\b|\bIND\b|India|Mumbai|Delhi|Bangalore/i],
    ["ID", "印尼", /印度尼西亚|印度尼西亞|印尼|雅加达|雅加達|🇮🇩|\bID\b|\bIDN\b|Indonesia|Jakarta/i],
    ["MY", "马来西亚", /马来西亚|馬來西亞|吉隆坡|🇲🇾|\bMY\b|\bMYS\b|Malaysia/i],
    ["TH", "泰国", /泰国|泰國|曼谷|🇹🇭|\bTH\b|\bTHA\b|Thailand|Bangkok/i],
    ["VN", "越南", /越南|河内|河內|胡志明|🇻🇳|\bVN\b|\bVNM\b|Viet[ -]?Nam|Hanoi|Ho[ -]?Chi[ -]?Minh/i],
    ["PH", "菲律宾", /菲律宾|菲律賓|马尼拉|馬尼拉|宿务|宿霧|🇵🇭|\bPH\b|\bPHL\b|Philippines|Manila|Cebu/i],
    ["TR", "土耳其", /土耳其|伊斯坦布尔|🇹🇷|\bTR\b|\bTUR\b|Turkey|Türkiye|Istanbul/i],
    ["AE", "阿联酋", /阿联酋|阿聯酋|迪拜|阿布扎比|🇦🇪|\bUAE\b|\bARE\b|Emirates|Dubai/i],
    ["RU", "俄罗斯", /俄罗斯|俄羅斯|莫斯科|🇷🇺|\bRU\b|\bRUS\b|Russia|Moscow/i],
    ["CH", "瑞士", /瑞士|苏黎世|蘇黎世|🇨🇭|\bCH\b|\bCHE\b|Switzerland|Zurich/i],
    ["SE", "瑞典", /瑞典|斯德哥尔摩|斯德哥爾摩|🇸🇪|\bSE\b|\bSWE\b|Sweden|Stockholm/i],
    ["FI", "芬兰", /芬兰|芬蘭|赫尔辛基|赫爾辛基|🇫🇮|\bFI\b|\bFIN\b|Finland|Helsinki/i],
    ["PL", "波兰", /波兰|波蘭|华沙|華沙|🇵🇱|\bPL\b|\bPOL\b|Poland|Warsaw/i],
    ["RO", "罗马尼亚", /罗马尼亚|羅馬尼亞|布加勒斯特|🇷🇴|\bRO\b|\bROU\b|Romania|Bucharest/i],
    ["LV", "拉脱维亚", /拉脱维亚|拉脫維亞|里加|🇱🇻|\bLV\b|\bLVA\b|Latvia|Riga/i],
    ["BR", "巴西", /巴西|圣保罗|聖保羅|🇧🇷|\bBR\b|\bBRA\b|Brazil|Brasil|SaoPaulo/i],
    ["AR", "阿根廷", /阿根廷|布宜诺斯艾利斯|🇦🇷|\bAR\b|\bARG\b|Argentina/i],
    ["BD", "孟加拉", /孟加拉|孟加拉國|达卡|達卡|🇧🇩|\bBD\b|\bBGD\b|Bangladesh|Dhaka/i]
];

function flagOf(code) {
    return String.fromCodePoint(
        0x1f1e6 + code.charCodeAt(0) - 65,
        0x1f1e6 + code.charCodeAt(1) - 65
    );
}

function regionLabel(region) {
    return flagOf(region[0]) + region[1] + "节点";
}

function isNodeOutbound(o) {
    return o && typeof o === "object" &&
        typeof o.tag === "string" && o.tag !== "" &&
        o.type !== "selector" && o.type !== "urltest" &&
        o.type !== "direct" && o.type !== "block" && o.type !== "dns";
}

function main(config) {
    if (!config || typeof config !== "object") return config;

    const outbounds = Array.isArray(config.outbounds) ? config.outbounds : [];
    const direct = outbounds.find(o => o && o.type === "direct") ||
        { type: "direct", tag: "direct" };
    const directTag = String(direct.tag || "direct");
    direct.tag = directTag;

    const nodes = outbounds.filter(isNodeOutbound);

    // 组名 / 内置 tag 不能被节点占用；只做最小避让，不做改名 / 地区名过滤。
    const reserved = new Set([
        PROXY_GROUP, AUTO_GROUP, MANUAL_GROUP, DIRECT_GROUP, directTag,
        ...APP_GROUP_NAMES,
        ...REGIONS.map(regionLabel)
    ]);
    const usedTags = new Set(reserved);
    nodes.forEach(node => {
        const base = node.tag;
        let tag = base;
        let suffix = 2;
        while (usedTags.has(tag)) tag = base + "-" + suffix++;
        node.tag = tag;
        usedTags.add(tag);
    });

    const nodeTags = nodes.map(node => node.tag);
    const activeRegions = REGIONS.map(region => ({
        region,
        label: regionLabel(region),
        tags: nodes.filter(node => region[2].test(node.tag)).map(node => node.tag)
    })).filter(item => item.tags.length >= REGION_MIN_NODES);

    const groups = [];

    if (nodeTags.length) {
        groups.push({
            type: "urltest",
            tag: AUTO_GROUP,
            outbounds: nodeTags,
            url: TEST_URL,
            interval: "5m",
            tolerance: 50
        });
    }

    groups.push({
        type: "selector",
        tag: MANUAL_GROUP,
        outbounds: nodeTags.length ? nodeTags : [directTag],
        default: nodeTags[0] || directTag
    });

    groups.push({
        type: "selector",
        tag: DIRECT_GROUP,
        outbounds: [directTag],
        default: directTag
    });

    activeRegions.forEach(item => {
        groups.push({
            type: "urltest",
            tag: item.label,
            outbounds: item.tags,
            url: TEST_URL,
            interval: "5m",
            tolerance: 50
        });
    });

    const regionGroups = activeRegions.map(item => item.label);
    const appMembers = [PROXY_GROUP, DIRECT_GROUP, MANUAL_GROUP, ...regionGroups];
    const appMembersDirectFirst = [DIRECT_GROUP, PROXY_GROUP, MANUAL_GROUP, ...regionGroups];

    APP_RULES.forEach(([name]) => {
        const members = name === "Microsoft"
            ? appMembersDirectFirst
            : appMembers;
        groups.push({
            type: "selector",
            tag: name,
            outbounds: members,
            default: name === "Microsoft" ? DIRECT_GROUP : PROXY_GROUP
        });
    });

    const proxyMembers = [];
    if (nodeTags.length) proxyMembers.push(AUTO_GROUP);
    proxyMembers.push(...regionGroups, MANUAL_GROUP, DIRECT_GROUP);
    groups.push({
        type: "selector",
        tag: PROXY_GROUP,
        outbounds: proxyMembers.length ? proxyMembers : [DIRECT_GROUP],
        default: nodeTags.length ? AUTO_GROUP : DIRECT_GROUP
    });

    config.outbounds = groups.concat(nodes, [direct]);

    // ── 规则集：Sing-Box 只认 .srs，mihomo 的 .mrs / yaml 不能直接用 ──
    const ruleSetMap = new Map();

    function useSet(name) {
        const tag = "geosite-" + name;
        if (!ruleSetMap.has(tag)) {
            ruleSetMap.set(tag, {
                type: "remote",
                tag,
                format: "binary",
                url: RULE_BASE + tag + ".srs",
                http_client: HTTP_CLIENT_TAG
            });
        }
        return tag;
    }

    function useIPSet(name) {
        const tag = "geoip-" + name;
        if (!ruleSetMap.has(tag)) {
            ruleSetMap.set(tag, {
                type: "remote",
                tag,
                format: "binary",
                url: IP_BASE + tag + ".srs",
                http_client: HTTP_CLIENT_TAG
            });
        }
        return tag;
    }

    const rules = [{ action: "sniff" }];

    rules.push({
        rule_set: [useSet("private")],
        action: "route",
        outbound: directTag
    });
    rules.push({
        ip_is_private: true,
        action: "route",
        outbound: directTag
    });
    rules.push({
        rule_set: [useSet("category-ads-all")],
        action: "reject"
    });

    // NTP 直连：很多节点不通 UDP 123，时间偏差会影响 TLS
    rules.push({
        network: "udp",
        port: 123,
        action: "route",
        outbound: directTag
    });

    if (BLOCK_QUIC) {
        rules.push({ network: "udp", port: 443, action: "reject" });
    }
    if (BLOCK_STUN) {
        rules.push({ network: "udp", port: [3478, 3479], action: "reject" });
        rules.push({ network: "udp", port_range: "19302:19309", action: "reject" });
    }
    if (BT_DIRECT) {
        rules.push({
            rule_set: [useSet("category-public-tracker"), useSet("category-pt")],
            action: "route",
            outbound: directTag
        });
    }

    // 自定义域名：直连在前、代理在后；.cn 直连放在应用规则之后，避免截胡 App 的国内 CDN。
    rules.push({
        domain_suffix: CUSTOM_PROXY,
        action: "route",
        outbound: PROXY_GROUP
    });

    APP_RULES.forEach(([group, sets]) => {
        rules.push({
            rule_set: sets.map(useSet),
            action: "route",
            outbound: group
        });
    });

    rules.push({
        rule_set: [useSet("geolocation-!cn")],
        action: "route",
        outbound: PROXY_GROUP
    });
    rules.push({
        domain_suffix: CUSTOM_DIRECT,
        action: "route",
        outbound: directTag
    });
    rules.push({
        rule_set: [useSet("cn")],
        action: "route",
        outbound: directTag
    });
    rules.push({
        rule_set: [useIPSet("cn")],
        action: "route",
        outbound: directTag
    });

    config.route = config.route || {};
    config.route.auto_detect_interface = true;
    config.route.final = PROXY_GROUP;
    config.route.rules = rules;
    config.route.rule_set = Array.from(ruleSetMap.values());
    config.route.default_http_client = HTTP_CLIENT_TAG;

    // 规则集缓存：避免每次启动都重新下载 23 个 .srs（SFA 的缓存目录由客户端管理）。
    config.experimental = config.experimental || {};
    config.experimental.cache_file = Object.assign(
        {},
        config.experimental.cache_file || {},
        { enabled: true }
    );

    // 规则集下载客户端：默认直连 jsDelivr；下不动时把 DOWNLOAD_VIA_DIRECT 改 false，
    // 下载会走「节点选择」。不要用已废弃的 download_detour。
    const clients = Array.isArray(config.http_clients)
        ? config.http_clients.filter(item => !item || item.tag !== HTTP_CLIENT_TAG)
        : [];
    clients.push({
        tag: HTTP_CLIENT_TAG,
        detour: DOWNLOAD_VIA_DIRECT ? directTag : PROXY_GROUP
    });
    config.http_clients = clients;

    return config;
}

if (typeof module !== "undefined") {
    module.exports = main;
    module.exports.main = main;
}
