package ddfinger

import (
	"FusionWeb/backend/core/ddout"
	"FusionWeb/backend/core/structs"
	"FusionWeb/backend/core/utils"
	"container/list"
	"fmt"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
)

// 判断优先级 非运算符返回0
func advance(ch int) int {
	// !
	if ch == 33 {
		return 3
	}
	// &
	if ch == 38 {
		return 2
	}
	// |
	if ch == 124 {
		return 1
	}
	return 0
}

// CleanExpression 清理表达式，修复常见的语法错误
// 自动修复常见的语法错误，如多余的括号、方括号等
func CleanExpression(expression string) string {
	// 移除多余的方括号对（如 ]] 或 [[）
	expression = strings.ReplaceAll(expression, "]]", "")
	expression = strings.ReplaceAll(expression, "[[", "")

	// 移除末尾多余的右括号（如果左括号数量少于右括号）
	leftCount := strings.Count(expression, "(")
	rightCount := strings.Count(expression, ")")
	if rightCount > leftCount {
		// 移除末尾多余的右括号
		diff := rightCount - leftCount
		for i := 0; i < diff; i++ {
			lastIndex := strings.LastIndex(expression, ")")
			if lastIndex >= 0 {
				expression = expression[:lastIndex] + expression[lastIndex+1:]
			}
		}
	}

	// 移除开头多余的左括号（如果右括号数量少于左括号）
	leftCount = strings.Count(expression, "(")
	rightCount = strings.Count(expression, ")")
	if leftCount > rightCount {
		// 移除开头多余的左括号
		diff := leftCount - rightCount
		for i := 0; i < diff; i++ {
			firstIndex := strings.Index(expression, "(")
			if firstIndex >= 0 {
				expression = expression[:firstIndex] + expression[firstIndex+1:]
			}
		}
	}

	return expression
}

// 计算纯bool表达式，支持 ! && & || | ( )
// 不再使用 Fatal()，改为记录错误并返回 false，避免程序闪退
func boolEval(expression string) bool {
	// 先清理表达式，修复常见的语法错误
	originalExpr := expression
	expression = CleanExpression(expression)
	if expression != originalExpr {
		gologger.Warning().Msg(fmt.Sprintf("[-] 检测到指纹规则表达式语法错误，已自动修复: [%s] -> [%s]", originalExpr, expression))
	}

	// 左右括号数量相等
	if strings.Count(expression, "(") != strings.Count(expression, ")") {
		// 使用 Error 而不是 Fatal，避免程序退出
		gologger.Error().Msg(fmt.Sprintf("[-] 纯布尔表达式 [%s] 左右括号不匹配（原始: [%s]），跳过该指纹规则", expression, originalExpr))
		return false // 返回 false，表示匹配失败
	}
	// 去除空格
	for strings.Contains(expression, " ") {
		expression = strings.ReplaceAll(expression, " ", "")
	}
	// 去除空表达式
	for strings.Contains(expression, "()") {
		expression = strings.ReplaceAll(expression, "()", "")
	}
	for strings.Contains(expression, "&&") {
		expression = strings.ReplaceAll(expression, "&&", "&")
	}
	for strings.Contains(expression, "||") {
		expression = strings.ReplaceAll(expression, "||", "|")
	}
	if !strings.Contains(expression, "T") && !strings.Contains(expression, "F") {
		return false
		// panic("纯布尔表达式错误，没有包含T/F")
	}

	expr := list.New()
	operator_stack := list.New()
	for _, ch := range expression {
		// ch 为 T或者F
		if ch == 84 || ch == 70 {
			expr.PushBack(int(ch))
		} else if advance(int(ch)) > 0 {
			if operator_stack.Len() == 0 {
				operator_stack.PushBack(int(ch))
				continue
			}
			// 两个!抵消
			if ch == 33 && operator_stack.Back().Value.(int) == 33 {
				operator_stack.Remove(operator_stack.Back())
				continue
			}
			for operator_stack.Len() != 0 && operator_stack.Back().Value.(int) != 40 && advance(operator_stack.Back().Value.(int)) >= advance(int(ch)) {
				e := operator_stack.Back()
				expr.PushBack(e.Value.(int))
				operator_stack.Remove(e)
			}
			operator_stack.PushBack(int(ch))

		} else if ch == 40 {
			operator_stack.PushBack(int(ch))
		} else if ch == 41 {
			// 添加栈空检查，避免括号不匹配时 panic
			if operator_stack.Len() == 0 {
				gologger.Error().Msg(fmt.Sprintf("[-] 纯布尔表达式 [%s] 右括号没有对应的左括号，跳过该指纹规则", expression))
				return false
			}
			for operator_stack.Len() > 0 && operator_stack.Back().Value.(int) != 40 {
				e := operator_stack.Back()
				expr.PushBack(e.Value.(int))
				operator_stack.Remove(e)
			}
			// 再次检查栈是否为空，避免移除空栈元素
			if operator_stack.Len() == 0 {
				gologger.Error().Msg(fmt.Sprintf("[-] 纯布尔表达式 [%s] 右括号没有对应的左括号，跳过该指纹规则", expression))
				return false
			}
			operator_stack.Remove(operator_stack.Back())
		}
	}
	for operator_stack.Len() != 0 {
		e := operator_stack.Back()
		expr.PushBack(e.Value.(int))
		operator_stack.Remove(e)
	}

	tf_stack := list.New()
	for expr.Len() != 0 {
		e := expr.Front()
		ch := e.Value.(int)
		expr.Remove(e)
		if ch == 84 || ch == 70 {
			tf_stack.PushBack(int(ch))
		}
		if ch == 38 { // &
			// 添加栈空检查，避免操作符缺少操作数时 panic
			if tf_stack.Len() < 2 {
				gologger.Error().Msg(fmt.Sprintf("[-] 纯布尔表达式 [%s] 操作符 & 缺少操作数，跳过该指纹规则", expression))
				return false
			}
			em := tf_stack.Back()
			a := em.Value.(int)
			tf_stack.Remove(em)
			em = tf_stack.Back()
			b := em.Value.(int)
			tf_stack.Remove(em)
			if a == 84 && b == 84 {
				tf_stack.PushBack(84)
			} else {
				tf_stack.PushBack(70)
			}
		}
		if ch == 124 { // |
			// 添加栈空检查，避免操作符缺少操作数时 panic
			if tf_stack.Len() < 2 {
				gologger.Error().Msg(fmt.Sprintf("[-] 纯布尔表达式 [%s] 操作符 | 缺少操作数，跳过该指纹规则", expression))
				return false
			}
			em := tf_stack.Back()
			a := em.Value.(int)
			tf_stack.Remove(em)
			em = tf_stack.Back()
			b := em.Value.(int)
			tf_stack.Remove(em)
			if a == 70 && b == 70 {
				tf_stack.PushBack(70)
			} else {
				tf_stack.PushBack(84)
			}
		}
		if ch == 33 { // !
			// 添加栈空检查，避免操作符缺少操作数时 panic
			if tf_stack.Len() < 1 {
				gologger.Error().Msg(fmt.Sprintf("[-] 纯布尔表达式 [%s] 操作符 ! 缺少操作数，跳过该指纹规则", expression))
				return false
			}
			em := tf_stack.Back()
			a := em.Value.(int)
			tf_stack.Remove(em)
			if a == 70 {
				tf_stack.PushBack(84)
			} else if a == 84 {
				tf_stack.PushBack(70)
			}
		}
	}
	// 添加栈空检查，避免访问空栈
	if tf_stack.Len() == 0 {
		gologger.Error().Msg(fmt.Sprintf("[-] 纯布尔表达式 [%s] 表达式为空，跳过该指纹规则", expression))
		return false
	}
	if tf_stack.Front().Value.(int) == 84 {
		return true
	} else {
		return false
	}

}

func getRuleData(rule string) structs.RuleData {
	if !strings.Contains(rule, "=\"") {
		return structs.RuleData{}
	}
	pos := strings.Index(rule, "=\"")

	// 添加边界检查，避免 pos-1 越界
	if pos <= 0 {
		return structs.RuleData{}
	}

	op := 0
	if rule[pos-1] == 33 {
		op = 1
	} else if rule[pos-1] == 61 {
		op = 2
	} else if rule[pos-1] == 62 {
		op = 3
	} else if rule[pos-1] == 60 {
		op = 4
	} else if rule[pos-1] == 126 {
		op = 5
	}

	start := 0
	ti := 0
	if op > 0 {
		ti = 1
	}
	for i := pos - 1 - ti; i >= 0; i-- {
		if (rule[i] > 122 || rule[i] < 97) && rule[i] != 95 {
			start = i + 1
			break
		}

	}

	// 添加边界检查，避免 slice bounds out of range [6:5]
	if start >= pos-ti {
		// 如果 start >= pos-ti，说明 key 为空或无效，返回空数据
		return structs.RuleData{}
	}
	if pos-ti > len(rule) {
		// 如果 pos-ti 超出字符串长度，返回空数据
		return structs.RuleData{}
	}
	key := rule[start : pos-ti]

	end := pos + 2
	for i := pos + 2; i < len(rule)-1; i++ {
		if rule[i] != 92 && rule[i+1] == 34 {
			end = i + 2
			break
		}
	}

	// 添加边界检查，避免 slice bounds out of range
	if end > len(rule) {
		end = len(rule)
	}
	if pos+2 >= end-1 {
		// 如果 pos+2 >= end-1，说明 value 为空或无效，返回空数据
		return structs.RuleData{}
	}
	if start >= end {
		// 如果 start >= end，说明 all 为空或无效，返回空数据
		return structs.RuleData{}
	}

	value := rule[pos+2 : end-1]
	all := rule[start:end]

	return structs.RuleData{Start: start, End: end, Op: int16(op), Key: key, Value: value, All: all}
}

func ParseRule(rule string) []structs.RuleData {
	var result []structs.RuleData
	empty := structs.RuleData{}

	// 保存原始规则，用于错误报告
	originalRule := rule

	for {
		data := getRuleData(rule)
		if data == empty {
			break
		}
		result = append(result, data)
		rule = rule[:data.Start] + "T" + rule[data.End:]
	}

	// 检查解析后的规则是否还有未解析的部分（可能是语法错误）
	// 清理表达式，移除多余的括号和方括号
	cleanedRule := CleanExpression(rule)
	if cleanedRule != rule {
		// 如果清理后还有变化，说明可能有语法错误
		gologger.Warning().Msg(fmt.Sprintf("[-] 指纹规则解析后检测到可能的语法错误: [%s] -> [%s] (原始规则: [%s])", rule, cleanedRule, originalRule))
	}

	return result
}

func regexMatch(pattern string, s string) (bool, error) {
	// 编译正则表达式，添加大小写不敏感标志
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(s), nil
}

// body="123"  op=0  dataSource为http.body dataRule=123
func dataCheckString(op int16, dataSource string, dataRule string) bool {
	// 先处理转义字符
	dataRule = strings.ReplaceAll(dataRule, "\\\"", "\"")

	// 对于正则表达式（op=5），不转换为小写，保持原始大小写进行匹配
	if op == 5 {
		rs, err := regexMatch(dataRule, dataSource)
		if err == nil && rs {
			return true
		}
		return false
	}

	// 对于其他操作符，转换为小写进行匹配
	dataSource = strings.ToLower(dataSource)
	dataRule = strings.ToLower(dataRule)

	if op == 0 {
		if strings.Contains(dataSource, dataRule) {
			return true
		}
	} else if op == 1 {
		if !strings.Contains(dataSource, dataRule) {
			return true
		}
	} else if op == 2 {
		if dataSource == dataRule {
			return true
		}
	}
	return false
}

func dataCheckInt(op int16, dataSource int, dataRule int) bool {
	if op == 0 || op == 2 { // 数字相等 (op=0 无操作符, op=2 是==)
		if dataSource == dataRule {
			return true
		}
	} else if op == 1 { // 数字不相等
		if dataSource != dataRule {
			return true
		}
	} else if op == 3 { // 大于等于
		if dataSource >= dataRule {
			return true
		}
	} else if op == 4 {
		if dataSource <= dataRule {
			return true
		}
	}
	return false
}

func checkPath(state *structs.FingerprintState,
	Path string,
	webPath structs.UrlPathEntity,
	Port int, // 所开放的端口
	Protocol string, // 协议
	Banner string, // 响应
	Cert string, // TLS证书
) []string {
	var fingerPrintResults []string

	isWeb := Path != "no#web" && webPath.Hash != ""

	hashString := webPath.Hash
	body := ""
	if state != nil && state.HTTPBodyHMap != nil && hashString != "" {
		if bodyBytes, ok := state.HTTPBodyHMap.Get(hashString); ok {
			body = string(bodyBytes)
		}
	}

	headerString := ""
	if state != nil && state.HTTPHeaderHMap != nil && webPath.HeaderHashString != "" {
		if headerBytes, ok := state.HTTPHeaderHMap.Get(webPath.HeaderHashString); ok {
			headerString = string(headerBytes)
		}
	}

	workers := runtime.NumCPU() * 2
	inputChan := make(chan structs.FingerPEntity, len(structs.FingerprintDB))
	defer close(inputChan)
	results := make(chan string, len(structs.FingerprintDB))
	defer close(results)

	var wg sync.WaitGroup

	//接收结果
	go func() {
		for found := range results {
			if found != "" {
				fingerPrintResults = append(fingerPrintResults, found)
			}
			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for finger := range inputChan {
				rules := finger.Rule
				product := finger.ProductName
				expr := finger.AllString

				for _, singleRule := range rules {
					singleRuleResult := false
					if singleRule.Key == "header" {
						if isWeb && dataCheckString(singleRule.Op, headerString, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "body" {
						// 检查响应体是否为空
						if !isWeb {
							// 如果不是Web服务，跳过body匹配
							singleRuleResult = false
						} else if body == "" {
							// 如果响应体为空，跳过匹配
							singleRuleResult = false
						} else if dataCheckString(singleRule.Op, body, singleRule.Value) {
							singleRuleResult = true
						} else {
							// 匹配失败，不记录日志（避免产生大量调试输出）
							singleRuleResult = false
						}
					} else if singleRule.Key == "server" {
						if isWeb && dataCheckString(singleRule.Op, webPath.Server, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "title" {
						if isWeb && dataCheckString(singleRule.Op, webPath.Title, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "cert" {
						if dataCheckString(singleRule.Op, Cert, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "port" {
						value, err := strconv.Atoi(singleRule.Value)
						if err == nil && dataCheckInt(singleRule.Op, Port, value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "protocol" {
						if singleRule.Op == 0 {
							if Protocol == singleRule.Value {
								singleRuleResult = true
							}
						} else if singleRule.Op == 1 {
							if Protocol != singleRule.Value {
								singleRuleResult = true
							}
						}
					} else if singleRule.Key == "path" {
						if isWeb && dataCheckString(singleRule.Op, Path, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "body_hash" {

						if isWeb && dataCheckString(singleRule.Op, webPath.Hash, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "icon_hash" {
						value, err := strconv.Atoi(singleRule.Value)
						hashIcon, errHash := strconv.Atoi(webPath.IconHash)
						if isWeb && err == nil && errHash == nil && dataCheckInt(singleRule.Op, hashIcon, value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "status" {
						value, err := strconv.Atoi(singleRule.Value)
						if isWeb && err == nil && dataCheckInt(singleRule.Op, webPath.StatusCode, value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "content_type" {
						if isWeb && dataCheckString(singleRule.Op, webPath.ContentType, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "banner" {
						if dataCheckString(singleRule.Op, Banner, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "type" {
						if singleRule.Value == "service" {
							singleRuleResult = true
						}
					}
					if singleRuleResult {
						expr = expr[:singleRule.Start] + "T" + expr[singleRule.End:]
					} else {
						expr = expr[:singleRule.Start] + "F" + expr[singleRule.End:]
					}
				}

				// 在调用 boolEval 前保存原始表达式，以便错误时记录指纹名称
				originalExpr := expr
				r := boolEval(expr)
				if r {
					results <- product
				} else {
					// 如果表达式有括号不匹配问题，记录指纹名称以便调试
					if strings.Count(originalExpr, "(") != strings.Count(originalExpr, ")") {
						gologger.Warning().Msg(fmt.Sprintf("指纹规则 [%s] 的布尔表达式括号不匹配: [%s]", product, originalExpr))
					}
					results <- ""
				}

			}

		}()
	}

	//添加扫描目标
	for _, input := range structs.FingerprintDB {
		wg.Add(1)
		inputChan <- input
	}
	wg.Wait()

	return utils.RemoveDuplicateElement(fingerPrintResults)
}

func FingerprintIdentification() {
	if structs.GlobalResultMap == nil {
		structs.GlobalResultMap = make(map[string][]string)
	}
	FingerprintIdentificationWithState(&structs.FingerprintState{
		URLMap:         structs.GlobalURLMap,
		ResultMap:      structs.GlobalResultMap,
		IPPortMap:      structs.GlobalIPPortMap,
		HTTPBodyHMap:   structs.GlobalHttpBodyHMap,
		HTTPHeaderHMap: structs.GlobalHttpHeaderHMap,
		BannerHMap:     structs.GlobalBannerHMap,
	})
}

func FingerprintIdentificationWithState(state *structs.FingerprintState) {
	if state == nil {
		return
	}
	if state.URLMap == nil {
		state.URLMap = make(map[string]structs.URLEntity)
	}
	if state.ResultMap == nil {
		state.ResultMap = make(map[string][]string)
	}
	if state.IPPortMap == nil {
		state.IPPortMap = make(map[string]string)
	}

	// 统计将要进行被动指纹识别的 URL 数量（来自获取Web响应与主动指纹路径爆破）
	urlsCount := 0
	for _, urlEntity := range state.URLMap {
		urlsCount += len(urlEntity.WebPaths)
	}
	// 移除日志输出：避免显示被动指纹探测的开始和URL数量信息

	// 先识别非Web
	for hostPort, protocol := range state.IPPortMap {
		if protocol == "http" || protocol == "https" || protocol == "" {
			continue
		}
		t := strings.Split(hostPort, ":")
		if len(t) != 2 {
			continue
		}
		// host := t[0]
		port, err := strconv.Atoi(t[1])
		if err != nil {
			continue
		}
		banner := ""
		if state.BannerHMap != nil {
			if bodyBytes, ok := state.BannerHMap.Get(hostPort); ok {
				banner = string(bodyBytes)
			}
		}
		results := checkPath(state, "no#web", structs.UrlPathEntity{}, port, protocol, banner, "")
		if len(results) > 0 {
			Url := fmt.Sprintf("%s://%s", protocol, hostPort)
			state.ResultMap[Url] = results

			//msg := "[Finger] " + Url + " ["
			//for _, r := range results {
			//	msg += aurora.Cyan(r).String() + ","
			//}
			//msg = msg[:len(msg)-1] + "]"
			//gologger.Silent().Msg(msg)

			ddout.FormatOutput(ddout.OutputMessage{
				Type:          "Finger",
				IP:            "",
				IPs:           nil,
				Port:          "",
				Protocol:      "",
				Web:           ddout.WebInfo{},
				Finger:        results,
				Domain:        "",
				URI:           Url,
				AdditionalMsg: "",
			})

		}

	}
	// 非Web服务识别完成

	// 开始识别Web服务
	for rootURL, urlEntity := range state.URLMap {
		// 处理 rootURL
		banner := ""
		if urlEntity.IP != "" {
			hostPort := fmt.Sprintf("%s:%d", urlEntity.IP, urlEntity.Port)
			if state.BannerHMap != nil {
				bodyBytes, ok := state.BannerHMap.Get(hostPort)
				if ok {
					banner = string(bodyBytes)
				}
			}
		}

		URL, _ := url.Parse(rootURL)

		for path, pathEntity := range urlEntity.WebPaths {
			results := checkPath(state, path, pathEntity, urlEntity.Port, URL.Scheme, banner, urlEntity.Cert)
			fullURL := rootURL + path

			if len(results) > 0 {
				state.ResultMap[fullURL] = results
				//msg := "[Finger] " + fullURL + " "
				//msg += fmt.Sprintf("[%d] [", pathEntity.StatusCode)
				//for _, r := range results {
				//	msg += aurora.Cyan(r).String() + ","
				//}
				//msg = msg[:len(msg)-1] + "]"
				//if pathEntity.Title != "" {
				//	msg += fmt.Sprintf(" [%s]", pathEntity.Title)
				//}
				//gologger.Silent().Msg(msg)
				ddout.FormatOutput(ddout.OutputMessage{
					Type:     "Finger",
					IP:       "",
					IPs:      nil,
					Port:     "",
					Protocol: "",
					Web: ddout.WebInfo{
						Status: strconv.Itoa(pathEntity.StatusCode),
						Title:  pathEntity.Title,
					},
					Finger:        results,
					Domain:        "",
					URI:           fullURL,
					AdditionalMsg: "",
				})
			} else {
				state.ResultMap[fullURL] = []string{}
			}
		}
	}
	// Web服务识别完成

	// 统计检测到的唯一指纹数量（去重）
	uniqueFingers := make(map[string]struct{})
	for _, results := range state.ResultMap {
		for _, r := range results {
			uniqueFingers[r] = struct{}{}
		}
	}
	gologger.Info().Msg(aurora.Red(fmt.Sprintf("共检测到 %d 个唯一指纹", len(uniqueFingers))).String())
	gologger.AuditTimeLogger("指纹识别结束")
	// FingerprintIdentification 函数结束
}

func SingleCheck(finger structs.FingerPEntity, Protocol string, headerString string, body string,
	Server string, Title string, Cert string, Port int, Path string, Hash string, IconHash string, StatusCode int,
	ContentType string, Banner string) bool {
	rules := finger.Rule
	expr := finger.AllString

	for _, singleRule := range rules {
		singleRuleResult := false
		if singleRule.Key == "header" {
			if dataCheckString(singleRule.Op, headerString, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "body" {
			if dataCheckString(singleRule.Op, body, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "server" {
			if dataCheckString(singleRule.Op, Server, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "title" {
			if dataCheckString(singleRule.Op, Title, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "cert" {
			if dataCheckString(singleRule.Op, Cert, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "port" {
			value, err := strconv.Atoi(singleRule.Value)
			if err == nil && dataCheckInt(singleRule.Op, Port, value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "protocol" {
			if singleRule.Op == 0 {
				if Protocol == singleRule.Value {
					singleRuleResult = true
				}
			} else if singleRule.Op == 1 {
				if Protocol != singleRule.Value {
					singleRuleResult = true
				}
			}
		} else if singleRule.Key == "path" {
			if dataCheckString(singleRule.Op, Path, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "body_hash" {

			if dataCheckString(singleRule.Op, Hash, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "icon_hash" {
			value, err := strconv.Atoi(singleRule.Value)
			hashIcon, errHash := strconv.Atoi(IconHash)
			if err == nil && errHash == nil && dataCheckInt(singleRule.Op, hashIcon, value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "status" {
			value, err := strconv.Atoi(singleRule.Value)
			if err == nil && dataCheckInt(singleRule.Op, StatusCode, value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "content_type" {
			if dataCheckString(singleRule.Op, ContentType, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "banner" {
			if dataCheckString(singleRule.Op, Banner, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "type" {
			if singleRule.Value == "service" {
				singleRuleResult = true
			}
		}
		if singleRuleResult {
			expr = expr[:singleRule.Start] + "T" + expr[singleRule.End:]
		} else {
			expr = expr[:singleRule.Start] + "F" + expr[singleRule.End:]
		}
	}

	// 在调用 boolEval 前检查表达式，如果括号不匹配则记录警告
	originalExpr := expr
	if strings.Count(originalExpr, "(") != strings.Count(originalExpr, ")") {
		gologger.Warning().Msg(fmt.Sprintf("指纹规则布尔表达式括号不匹配: [%s]", originalExpr))
	}
	return boolEval(expr)
}
