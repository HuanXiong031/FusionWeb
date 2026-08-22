// ========================================
// 包 http: HTTPx 回调与 Web 资产处理模块
//
// 功能概述：
//
//	处理 HTTPx 扫描器的所有回调结果，维护 Web 资产的全局数据结构，
//	并基于指纹识别结果生成 Nuclei 漏洞扫描的目标→POC 映射。
//
// 核心子模块：
//   1. UrlCallBack:          处理 HTTPx 的 Web 资产发现结果
//   2. DirBruteCallBack:     处理目录爆破的主动指纹识别结果
//   3. HostBindHTTPxCallBack: 处理域名绑定资产的发现结果
//   4. GetPocs:              根据指纹匹配工作流规则生成 POC 扫描计划
//   5. URLParse / AddYamlSuffix: URL 解析与文件名字符串处理工具函数
//
// 全局数据结构（写入操作）：
//   - GlobalURLMap:       RootURL → URLEntity（IP、端口、WebPath、证书等）
//   - GlobalHttpBodyHMap:  Body MD5 Hash → Body 内容（去重缓存）
//   - GlobalHttpHeaderHMap: Header MD5 Hash → Header 内容（去重缓存）
//   - GlobalResultMap:    RootURL → 指纹列表（识别的产品/框架）
//
// 指纹匹配工作流（GetPocs）：
//   - RootType: POC 适用于根 URL（scheme://host）
//   - BaseType: POC 适用于完整路径（scheme://host/path）
//   - DirType:  POC 适用于每一级子目录
//   - General-Poc: 通用 POC（不受指纹限制，所有目标执行）
//
// 集成关系：
//   - HTTPx 扫描结果 → UrlCallBack/HostBindHTTPxCallBack → GlobalURLMap
//   - 目录爆破结果 → DirBruteCallBack → GlobalResultMap（指纹识别）
//   - 指纹 + 工作流规则 → GetPocs → NucleiParams.TargetAndPocsName
//   - 依赖 engine/lib/ddfinger 库进行单次指纹匹配
//   - 通过 ddout 输出标准化结果（Web/Active-Finger/Domain-Bind 类型）
//
// ========================================
package http

import (
	"FusionWeb/backend/core/ddout"
	"FusionWeb/backend/core/structs"
	"FusionWeb/backend/core/utils"
	"FusionWeb/backend/engine/lib/ddfinger"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
)

// UrlCallBack 处理 HTTPx 扫描结果，建立 RootURL → URLEntity 的映射
//
// 功能说明：
//
//	HTTPx 扫描器每发现一个 Web 响应就调用此回调。
//	此函数维护全局 URL 数据结构（GlobalURLMap），去重相同 RootURL 下的不同路径，
//	缓存 Body 和 Header 内容（通过 MD5 Hash 去重），并输出标准化 Web 结果。
//
// 处理逻辑：
//  1. 获取最终 URL（FinalURL 或原始 URL）
//  2. 解析 URL，提取 scheme、host、path
//  3. 若 RootURL 已存在：检查 path 是否已记录，新路径则追加 WebPath 条目
//  4. 若 RootURL 不存在：创建新的 URLEntity（IP、端口、证书、首个 WebPath）
//  5. Body 和 Header 通过 MD5 Hash 缓存到全局 HashMap（节省内存）
//  6. 通过 ddout 输出 Type="Web" 的标准化结果
//
// 参数：
//   - resp: HTTPx 的扫描结果（包含 URL、状态码、标题、Body、Header、TLS 等）
//
// 全局变量写入：
//   - structs.GlobalURLMap: 新增或更新 URLEntity
//   - structs.GlobalHttpBodyHMap: 缓存响应 Body（MD5 → []byte）
//   - structs.GlobalHttpHeaderHMap: 缓存响应 Header（MD5 → []byte）
func UrlCallBack(resp runner.Result) {

	finalUrl := ""
	if resp.FinalURL != "" {
		finalUrl = resp.FinalURL
	} else {
		finalUrl = resp.URL
	}

	url := URLParse(finalUrl)
	pth := url.Path
	if pth == "" {
		pth = "/"
	}
	rootURL := fmt.Sprintf("%s://%s", url.Scheme, url.Host)
	structs.GlobalURLMapLock.Lock()
	_, rootURLOK := structs.GlobalURLMap[rootURL]
	structs.GlobalURLMapLock.Unlock()
	if rootURLOK {
		// 有这个root，查看这个path，如果没这个path再加
		structs.GlobalURLMapLock.Lock()
		_, pathOK := structs.GlobalURLMap[rootURL].WebPaths[pth]
		structs.GlobalURLMapLock.Unlock()
		if !pathOK {
			// 没有这个path
			md5 := resp.Hashes["body_md5"].(string)
			headerMd5 := resp.Hashes["header_md5"].(string)
			_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
			_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))
			structs.GlobalURLMapLock.Lock()
			structs.GlobalURLMap[rootURL].WebPaths[pth] = structs.UrlPathEntity{
				Hash:             md5,
				Title:            resp.Title,
				StatusCode:       resp.StatusCode,
				ContentType:      resp.ContentType,
				Server:           resp.WebServer,
				ContentLength:    resp.ContentLength,
				HeaderHashString: headerMd5,
				IconHash:         resp.FavIconMMH3,
			}
			structs.GlobalURLMapLock.Unlock()

			ddout.FormatOutput(ddout.OutputMessage{
				Type: "Web",
				IP:   "",
				Port: "",
				URI:  resp.URL,
				Web: ddout.WebInfo{
					Status: strconv.Itoa(resp.StatusCode),
					Title:  resp.Title,
				},
			})

		}
	} else {
		// 没有这个url

		port, err := strconv.Atoi(resp.Port)
		if err != nil {
			port = 0
		}

		md5 := resp.Hashes["body_md5"].(string)
		headerMd5 := resp.Hashes["header_md5"].(string)
		_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
		_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))

		webPath := structs.UrlPathEntity{
			Hash:             md5,
			Title:            resp.Title,
			StatusCode:       resp.StatusCode,
			ContentType:      resp.ContentType,
			Server:           resp.WebServer,
			ContentLength:    resp.ContentLength,
			HeaderHashString: headerMd5,
			IconHash:         resp.FavIconMMH3,
		}

		urlE := structs.URLEntity{
			IP:       resp.Host,
			Port:     port,
			WebPaths: nil,
			Cert:     getTLSString(resp),
		}

		urlE.WebPaths = make(map[string]structs.UrlPathEntity)
		urlE.WebPaths[pth] = webPath

		structs.GlobalURLMapLock.Lock()
		structs.GlobalURLMap[rootURL] = urlE
		structs.GlobalURLMapLock.Unlock()

		ddout.FormatOutput(ddout.OutputMessage{
			Type: "Web",
			IP:   "",
			Port: "",
			URI:  resp.URL,
			Web: ddout.WebInfo{
				Status: strconv.Itoa(resp.StatusCode),
				Title:  resp.Title,
			},
		})
	}

}

// getTLSString 将 HTTPx 的 TLSData 转换为可读字符串
//
// 功能说明：
//
//	提取 TLS/SSL 证书中的关键信息（Subject、Issuer），
//	格式化为多行字符串，供报告输出使用。
//
// 参数：
//   - resp: HTTPx 的扫描结果
//
// 返回值：
//   - 格式化的 TLS 证书信息字符串，包含 SubjectCN、SubjectDN、IssuerCN、IssuerDN、IssuerOrg
//   - 若无 TLS 数据则返回空字符串
func getTLSString(resp runner.Result) string {
	result := ""
	if resp.TLSData == nil {
		return result
	}

	result += "SubjectCN: " + resp.TLSData.SubjectCN + "\n"
	result += "SubjectDN: " + resp.TLSData.SubjectDN + "\n"

	result += "IssuerCN: " + resp.TLSData.IssuerCN + "\n"
	result += "IssuerDN: " + resp.TLSData.IssuerDN + "\n"

	result += "IssuerOrg: \n"
	for _, v := range resp.TLSData.IssuerOrg {
		result += "    - " + v + "\n"
	}

	return result

}

// URLParse 安全解析 URL 字符串为 *url.URL
//
// 功能说明：
//
//	封装 Go 标准库的 url.Parse，忽略解析错误（返回 nil）。
//	用于内部 URL 处理，简化代码中的错误处理。
//
// 参数：
//   - URLRaw: 原始 URL 字符串
//
// 返回值：
//   - 解析后的 *url.URL 对象；解析失败时返回空 URL
func URLParse(URLRaw string) *url.URL {
	URL, _ := url.Parse(URLRaw)
	return URL
}

// AddYamlSuffix 规范化 POC 名称，统一追加 .yaml 后缀
//
// 功能说明：
//
//	如果 POC 文件名不包含 .yaml 后缀，则自动追加。
//	确保 POC 文件名格式统一，便于后续模板文件查找。
//
// 参数：
//   - s: POC 文件名（可带或不带 .yaml 后缀）
//
// 返回值：
//   - 带有 .yaml 后缀的文件名
//
// 示例：
//   AddYamlSuffix("cve-2021-44228")      → "cve-2021-44228.yaml"
//   AddYamlSuffix("cve-2021-44228.yaml") → "cve-2021-44228.yaml"
func AddYamlSuffix(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, ".yaml") {
		return s
	} else {
		return s + ".yaml"
	}
}

// addPocs 将工作流规则中的 POC 名称添加到目标集合（去重合并）
//
// 功能说明：
//
//	辅助函数，用于向目标→POC 映射中添加 POC 条目。
//	若目标已存在则跳过重复的 POC 名称，避免重复扫描。
//
// 参数：
//   - target: 目标 URL
//   - result: 目标→POC 列表的映射（通过指针直接修改）
//   - workflowEntity: 包含 POC 列表的工作流规则实体
//
// 去重逻辑：
//   - 若目标未注册：直接添加所有 POC
//   - 若目标已注册：仅添加不存在的 POC 名称
//   - POC 名称统一追加 .yaml 后缀
func addPocs(target string, result *map[string][]string, workflowEntity structs.WorkFlowEntity) {
	// 判断有没有加入过
	_, ok := (*result)[target]
	if !ok { // 没有添加过这个目标
		(*result)[target] = []string{}
		for _, pocName := range workflowEntity.PocsName {
			(*result)[target] = append((*result)[target], AddYamlSuffix(pocName))
			gologger.AuditLogger("%s", "    - "+pocName)
		}
	} else { // 添加过就逐个比较
		existPocNames, _ := (*result)[target]
		for _, pocName := range workflowEntity.PocsName {
			// 没有就添加
			if utils.GetItemInArray(existPocNames, pocName) == -1 {
				(*result)[target] = append((*result)[target], AddYamlSuffix(pocName))
				gologger.AuditLogger("%s", "    - "+pocName)
			}
		}
	}
}

// GetPocs 根据已识别指纹与工作流规则生成待测目标→POC 列表
//
// 功能说明：
//
//	这是连接"指纹识别"和"漏洞扫描"的关键桥梁函数。
//	遍历 GlobalResultMap 中所有目标及其识别的指纹，在工作流数据库中匹配对应规则，
//	生成每个目标的 POC 扫描清单。支持三种匹配范围：
//
//	1. RootType（根路径匹配）:
//	   POC 适用于 scheme://host，忽略具体路径
//	   例如：指纹"Apache" → 对 https://target.com 执行 Apache 相关 POC
//
//	2. BaseType（完整路径匹配）:
//	   POC 适用于完整 URL scheme://host/path
//	   例如：指纹"Jenkins" → 对 https://target.com/jenkins 执行 Jenkins 相关 POC
//
//	3. DirType（子目录递归匹配）:
//	   POC 适用于 URL 路径的每一级子目录
//	   例如：URL https://target.com/a/b/c → 为 /a, /a/b, /a/b/c 分别生成条目
//
//	4. General-Poc（通用 POC）:
//	   不受指纹限制，对所有已识别的目标执行
//
// 参数：
//   - workflowDB: 指纹名称 → WorkFlowEntity 的工作流数据库
//     WorkFlowEntity 包含：PocNames、RootType、BaseType、DirType
//
// 返回值：
//   - map[string][]string: 目标URL → POC文件名列表的映射（供 NucleiParams.TargetAndPocsName 使用）
//   - int: 生成的 POC 条目总数（用于日志报告）
//
// 全局变量读取：
//   - structs.GlobalResultMap: 目标URL → 指纹名称列表
//   - structs.GlobalConfig.DisableGeneralPoc: 是否禁用通用 POC
func GetPocs(workflowDB map[string]structs.WorkFlowEntity) (map[string][]string, int) {
	gologger.AuditTimeLogger("根据指纹选择Poc")
	result := make(map[string][]string)
	count := 0

	var generalKeys []string
	if !structs.GlobalConfig.DisableGeneralPoc {
		for k, workflowEntity := range workflowDB {
			if strings.Contains(k, "General-Poc-") {
				if len(workflowEntity.PocsName) == 0 {
					continue
				}
				generalKeys = append(generalKeys, k)
			}
		}
	}

	for target, fingerprints := range structs.GlobalResultMap {
		gologger.AuditLogger("%s:", target)
		for _, finger := range fingerprints {
			workflowEntity, ok := workflowDB[finger]
			if !ok || len(workflowEntity.PocsName) == 0 {
				continue
			}

			if !strings.Contains(target, "http") {
				if !workflowEntity.RootType { // 与Root无关
					continue
				}
				addPocs(target, &result, workflowEntity)
				count++
			} else {
				Url := URLParse(target)

				// Web
				if workflowEntity.RootType {
					rootURL := fmt.Sprintf("%s://%s", Url.Scheme, Url.Host)
					addPocs(rootURL, &result, workflowEntity)
					count++

				}

				if (Url.Path != "/" && Url.Path != "") && workflowEntity.BaseType {
					addPocs(target, &result, workflowEntity)
					count++
				}

				if (Url.Path != "/" && Url.Path != "") && workflowEntity.DirType {
					splitPath := strings.Split(Url.Path, "/")
					for i := 1; i < len(splitPath); i++ {
						newPath := strings.Join(splitPath[:i], "/")
						t := fmt.Sprintf("%s://%s%s", Url.Scheme, Url.Host, newPath)
						addPocs(t, &result, workflowEntity)
						count++
					}

				}
			}

		}

		for _, key := range generalKeys {
			workflowEntity, ok := workflowDB[key]
			if !ok || len(workflowEntity.PocsName) == 0 {
				continue
			}

			if !strings.Contains(target, "http") {
				if !workflowEntity.RootType { // 与Root无关
					continue
				}
				addPocs(target, &result, workflowEntity)
				count++
			} else {
				Url := URLParse(target)

				// Web
				if workflowEntity.RootType {
					rootURL := fmt.Sprintf("%s://%s", Url.Scheme, Url.Host)
					addPocs(rootURL, &result, workflowEntity)
					count++
				}

				if (Url.Path != "/" && Url.Path != "") && workflowEntity.BaseType {
					addPocs(target, &result, workflowEntity)
					count++
				}

				if (Url.Path != "/" && Url.Path != "") && workflowEntity.DirType {
					splitPath := strings.Split(Url.Path, "/")
					for i := 1; i < len(splitPath); i++ {
						newPath := strings.Join(splitPath[:i], "/")
						t := fmt.Sprintf("%s://%s%s", Url.Scheme, Url.Host, newPath)
						addPocs(t, &result, workflowEntity)
						count++
					}

				}
			}
		}

	}
	return result, count
}

// DirBruteCallBack 处理目录爆破结果的回调函数
//
// 功能说明：
//
//	当目录爆破发现某个路径存在时（如 /admin/login），触发主动指纹识别。
//	流程：
//	1. 检查响应的路径是否匹配 DirDB 中的字典路径
//	2. 对匹配的路径，获取关联的产品名称列表
//	3. 遍历 FingerprintDB，对每个关联产品执行单次指纹匹配（ddfinger.SingleCheck）
//	4. 若指纹匹配成功，将产品名称添加到 GlobalResultMap 中对应 RootURL 的指纹列表
//	5. 输出 Type="Active-Finger" 的发现结果
//
// 参数：
//   - resp: HTTPx 目录爆破的响应结果（包含 URL、状态码、Body、Header 等）
//
// 数据流：
//   DirDB[path] → productNames → FingerprintDB → ddfinger.SingleCheck → GlobalResultMap
//
// 注意事项：
//   - 仅当指纹匹配成功时才更新 GlobalResultMap 和输出结果
//   - 对同一 RootURL 的同一产品名会去重（避免重复识别）
func DirBruteCallBack(resp runner.Result) {
	var Paths []string
	for dbPath, _ := range structs.DirDB {
		if strings.HasSuffix(resp.Path, dbPath) {
			Paths = append(Paths, dbPath)
		}
	}

	for _, path := range Paths {
		productNames := structs.DirDB[path]
		for _, productName := range productNames {
			success := false
			for _, v := range structs.FingerprintDB {
				if success {
					break
				}
				if v.ProductName == productName {
					portInt, err := strconv.Atoi(resp.Port)
					if err != nil {
						portInt = -1
					}
					r := ddfinger.SingleCheck(v, resp.Scheme, resp.Header, resp.Body, resp.WebServer, resp.Title, getTLSString(resp),
						portInt, resp.Path, "0", "0", resp.StatusCode, resp.ContentType, "")
					// 满足这个products的要求
					if r {
						success = true
						// 给对应的urlEntry添加指纹
						Url := URLParse(resp.URL)
						rootURL := fmt.Sprintf("%s://%s", Url.Scheme, Url.Host)

						// 将主动指纹识别结果添加到GlobalResultMap
						if structs.GlobalResultMap == nil {
							structs.GlobalResultMap = make(map[string][]string)
						}
						// 检查是否已存在，避免重复
						exists := false
						for _, fp := range structs.GlobalResultMap[rootURL] {
							if fp == productName {
								exists = true
								break
							}
						}
						if !exists {
							structs.GlobalResultMap[rootURL] = append(structs.GlobalResultMap[rootURL], productName)
						}

						structs.GlobalURLMapLock.Lock()
						_, rootURLOk := structs.GlobalURLMap[rootURL]
						structs.GlobalURLMapLock.Unlock()
						if rootURLOk {
							// 如果爆破来源上一步验活，那这里必然存在rootURL.
							// 有这个root，查看这个path，如果没这个path再加
							// 规范化路径处理
							pth := Url.Path
							if pth == "" {
								pth = "/"
							}
							structs.GlobalURLMapLock.Lock()
							_, pathOK := structs.GlobalURLMap[rootURL].WebPaths[pth]
							structs.GlobalURLMapLock.Unlock()
							if !pathOK {
								// 没有这个path
								md5 := resp.Hashes["body_md5"].(string)
								headerMd5 := resp.Hashes["header_md5"].(string)
								_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
								_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))
								structs.GlobalURLMapLock.Lock()
								structs.GlobalURLMap[rootURL].WebPaths[pth] = structs.UrlPathEntity{
									Hash:             md5,
									Title:            resp.Title,
									StatusCode:       resp.StatusCode,
									ContentType:      resp.ContentType,
									Server:           resp.WebServer,
									ContentLength:    resp.ContentLength,
									HeaderHashString: headerMd5,
									IconHash:         resp.FavIconMMH3,
								}
								structs.GlobalURLMapLock.Unlock()
							}

							ddout.FormatOutput(ddout.OutputMessage{
								Type:          "Active-Finger",
								IP:            "",
								IPs:           nil,
								Port:          "",
								Protocol:      "",
								Web:           ddout.WebInfo{},
								Finger:        []string{productName},
								Domain:        "",
								URI:           resp.URL,
								AdditionalMsg: "",
							})
							// gologger.Silent().Msgf("[Active-Finger] %s [%s]", resp.URL, productName)
						}
					}
				}
			}
		}
	}
}

// HostBindHTTPxCallBack 处理域名绑定资产发现的回调函数
//
// 功能说明：
//
//	当通过域名绑定（Host-Bind）方式访问某个 URL 时，此回调对比新响应
//	与已有的同名路径（基于 IP 的原始响应）是否一致。
//	若状态码或内容 Hash 不同，则标记为"新发现"的域名绑定资产，输出到结果。
//
// 处理流程：
//  1. 从 resp.A 获取解析到的 IP 列表
//  2. 遍历 GlobalURLMap 查找匹配的 URL（相同 Scheme、IP、Port、Path）
//  3. 对比现有路径的状态码和 Body Hash
//  4. 若不同（newWeb=true），输出 Type="Domain-Bind" 的发现
//  5. 将新发现的路径/URL 添加到 GlobalURLMap（与 UrlCallBack 相同逻辑）
//
// 参数：
//   - resp: HTTPx 的响应结果
//
// 输出类型：
//   - Type="Domain-Bind"：发现了与原始 IP 访问不同的域名绑定资产
//
// 注意事项：
//   - 仅当响应与已知结果不同时才记录（避免重复发现）
//   - 结果同时通过 ddout 输出和更新 GlobalURLMap
func HostBindHTTPxCallBack(resp runner.Result) {
	ips := resp.A
	path := resp.Path
	newWeb := false
	for _, ip := range ips {
		structs.GlobalURLMapLock.Lock()
		for rootURL, urlEntry := range structs.GlobalURLMap {
			URL, err := url.Parse(rootURL)
			if err != nil {
				continue
			}
			if URL.Scheme != resp.Scheme {
				continue
			}
			if urlEntry.IP != ip {
				continue
			}
			port := strconv.Itoa(urlEntry.Port)
			if port != resp.Port {
				continue
			}

			existPath, ok := urlEntry.WebPaths[path]
			if !ok {
				continue
			}

			if existPath.StatusCode != resp.StatusCode || existPath.Hash != existPath.Hash {
				newWeb = true
			}

		}
		structs.GlobalURLMapLock.Unlock()
	}

	if !newWeb {
		return
	}

	ddout.FormatOutput(ddout.OutputMessage{
		Type:     "Domain-Bind",
		IP:       "",
		IPs:      nil,
		Port:     "",
		Protocol: "",
		Web: ddout.WebInfo{
			Status: strconv.Itoa(resp.StatusCode),
		},
		Finger:        nil,
		Domain:        "",
		URI:           resp.URL,
		AdditionalMsg: resp.Title,
	})

	//if resp.Title != "" {
	//	gologger.Silent().Msgf("[Domain-Bind] [%v] %v [%v]", resp.StatusCode, resp.URL, resp.Title)
	//} else {
	//	gologger.Silent().Msgf("[Domain-Bind] [%v] %v", resp.StatusCode, resp.URL)
	//}

	finalUrl := ""
	if resp.FinalURL != "" {
		finalUrl = resp.FinalURL
	} else {
		finalUrl = resp.URL
	}

	urlFinal := URLParse(finalUrl)
	rootURL := fmt.Sprintf("%s://%s", urlFinal.Scheme, urlFinal.Host)
	structs.GlobalURLMapLock.Lock()
	_, rootURLOK := structs.GlobalURLMap[rootURL]
	structs.GlobalURLMapLock.Unlock()
	if rootURLOK {
		// 有这个root，查看这个path，如果没这个path再加
		structs.GlobalURLMapLock.Lock()
		_, pathOK := structs.GlobalURLMap[rootURL].WebPaths[urlFinal.Path]
		structs.GlobalURLMapLock.Unlock()
		if !pathOK {
			// 没有这个path
			md5 := resp.Hashes["body_md5"].(string)
			headerMd5 := resp.Hashes["header_md5"].(string)
			_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
			_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))
			structs.GlobalURLMapLock.Lock()
			structs.GlobalURLMap[rootURL].WebPaths[urlFinal.Path] = structs.UrlPathEntity{
				Hash:             md5,
				Title:            resp.Title,
				StatusCode:       resp.StatusCode,
				ContentType:      resp.ContentType,
				Server:           resp.WebServer,
				ContentLength:    resp.ContentLength,
				HeaderHashString: headerMd5,
				IconHash:         resp.FavIconMMH3,
			}
			structs.GlobalURLMapLock.Unlock()
		}
	} else {
		// 没有这个url

		port, err := strconv.Atoi(resp.Port)
		if err != nil {
			port = 0
		}

		md5 := resp.Hashes["body_md5"].(string)
		headerMd5 := resp.Hashes["header_md5"].(string)
		_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
		_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))

		webPath := structs.UrlPathEntity{
			Hash:             md5,
			Title:            resp.Title,
			StatusCode:       resp.StatusCode,
			ContentType:      resp.ContentType,
			Server:           resp.WebServer,
			ContentLength:    resp.ContentLength,
			HeaderHashString: headerMd5,
			IconHash:         resp.FavIconMMH3,
		}

		urlE := structs.URLEntity{
			IP:       resp.Host,
			Port:     port,
			WebPaths: nil,
			Cert:     getTLSString(resp),
		}

		urlE.WebPaths = make(map[string]structs.UrlPathEntity)
		urlE.WebPaths[urlFinal.Path] = webPath

		structs.GlobalURLMapLock.Lock()
		structs.GlobalURLMap[rootURL] = urlE
		structs.GlobalURLMapLock.Unlock()
	}

}
