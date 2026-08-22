// ========================================
// 包 common: 域名绑定资产发现模块（Host-Bind Discovery）
//
// 功能概述：
//
//	当一个 IP 地址上绑定了多个域名时，通过已发现的域名为已知的 Web 资产
//	构造新的 URL 并访问，以发现隐藏在域名绑定后的额外资产。
//	实现原理：如果 IP A 上发现了 RootURL（如 https://1.2.3.4:8443），
//	且该 IP 在 DNS 解析阶段关联了多个域名，则用这些域名替换 IP 后发起
//	HTTP 探测和目录爆破。
//
// 工作流程：
//  1. 遍历 structs.GlobalURLMap（已发现的 Web 根 URL）
//  2. 提取 URL 中的 IP 地址和端口
//  3. 从 structs.GlobalIPDomainMap 查找该 IP 对应的所有域名
//  4. 用每个域名替换 IP 构造新的 URL
//  5. 调用 httpx 的 DirBrute 进行目录爆破
//  6. 结果通过 HostBindHTTPxCallBack 回调处理
//
// 集成关系：
//   - 输入：structs.GlobalURLMap（HTTPx 扫描结果）
//   - 输入：structs.GlobalIPDomainMap（DNS 解析结果）
//   - 输出：通过 HostBindHTTPxCallBack 回调处理新发现的资产
//
// ========================================
package common

import (
	"FusionWeb/backend/core/structs"
	"FusionWeb/backend/core/utils"
	"FusionWeb/backend/engine/common/http"
	"fmt"
	"net/url"
	"strings"

	httpxlib "github.com/projectdiscovery/httpx"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
)

// HostBindCheck 基于 GlobalIPDomainMap 与已发现的 RootURL 构造域名绑定访问，并进行目录爆破
//
// 功能说明：
//
//	遍历已发现的所有 Web 根 URL（GlobalURLMap），提取其中使用 IP 地址作为 Host 的 URL，
//	然后查找该 IP 对应的域名列表（GlobalIPDomainMap），用域名替换 IP 后生成新的 URL。
//	最后调用 httpx 的 DirBrute 对这些新 URL 进行目录爆破，以发现域名绑定下的隐藏资产。
//
// 处理逻辑：
//  1. 遍历 GlobalURLMap 中的每个 rootURL
//  2. 解析 URL，判断 Host 是否包含端口（如 "1.2.3.4:8443"）
//  3. 提取 IP 部分，验证是否为合法的 IPv4 地址
//  4. 查找该 IP 在 GlobalIPDomainMap 中关联的所有域名
//  5. 用域名替换 IP 构造新 URL（保留协议和端口）
//  6. 对新生成的 URL 列表去重
//  7. 调用 httpxlib.DirBrute 进行目录爆破，回调使用 HostBindHTTPxCallBack
//
// 全局变量依赖：
//   - structs.GlobalURLMap：已发现的 Web 根 URL 映射
//   - structs.GlobalIPDomainMap：IP 到域名列表的映射
//   - structs.GlobalConfig.HTTPProxy：HTTP 代理配置
//   - structs.GlobalConfig.WebThreads：Web 扫描线程数
//   - structs.GlobalConfig.WebTimeout：Web 请求超时时间
//
// 输出：
//   - 发现的域名绑定资产通过 HostBindHTTPxCallBack 回调处理
func HostBindCheck() {
	gologger.Info().Msg(aurora.Red("域名绑定资产发现").String())

	var urls []string
	for rootURL, _ := range structs.GlobalURLMap {
		URL, err := url.Parse(rootURL)
		if err != nil {
			continue
		}

		if strings.Contains(URL.Host, ":") {
			tmp := strings.Split(URL.Host, ":")
			if len(tmp) != 2 {
				continue
			}
			ip, port := tmp[0], tmp[1]
			if !utils.IsIPv4(ip) {
				continue
			}
			domains, ok := structs.GlobalIPDomainMap[ip]
			if !ok {
				continue
			}
			for _, domain := range domains {
				urls = append(urls, fmt.Sprintf("%v://%v:%v", URL.Scheme, domain, port))
			}
		} else {
			ip := URL.Host
			if !utils.IsIPv4(ip) {
				continue
			}
			domains, ok := structs.GlobalIPDomainMap[ip]
			if !ok {
				continue
			}
			for _, domain := range domains {
				urls = append(urls, fmt.Sprintf("%v://%v", URL.Scheme, domain))
			}
		}
	}
	urls = utils.RemoveDuplicateElement(urls)

	httpxlib.DirBrute(urls, http.HostBindHTTPxCallBack,
		structs.GlobalConfig.HTTPProxy,
		structs.GlobalConfig.WebThreads,
		structs.GlobalConfig.WebTimeout,
		"hostbind",
		false)
	gologger.AuditTimeLogger("%s", aurora.Red("域名绑定资产发现结束").String())
}
