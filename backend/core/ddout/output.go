// 包 ddout: 统一输出与报告写入
// 该文件负责将不同阶段的结果（Alive/PortScan/Web/Finger/Nuclei 等）
// 规范化为文本或 JSON，并支持写入到指定文件。
package ddout

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
)

// 全局输出配置变量
var (
	OutputType     string // 输出格式类型："text" 或 "json"
	OutputFileName string // 输出文件路径，为空时仅输出到控制台
)

// WebInfo Web 页面基本信息
// 在扫描结果中携带 HTTP 响应状态码与页面标题
type WebInfo struct {
	Status string `json:"status,omitempty"` // HTTP 状态码（如 200、404）
	Title  string `json:"title,omitempty"`  // HTML <title> 标签内容
}

// OutputMessage 标准化输出结构
// 用于兼容不同扫描阶段的结果类型（存活检测/端口扫描/指纹/Nuclei 等）
// 各类扫描结果统一通过此结构体进行格式化输出
type OutputMessage struct {
	Type          string   `json:"type,omitempty"`
	IP            string   `json:"ip,omitempty"`
	IPs           []string `json:"ips,omitempty"`
	Port          string   `json:"port,omitempty"`
	Protocol      string   `json:"protocol,omitempty"`
	Web           WebInfo  `json:"web,omitempty"`
	Finger        []string `json:"finger,omitempty"`
	Domain        string   `json:"domain,omitempty"`
	URI           string   `json:"uri,omitempty"`
	City          string   `json:"city,omitempty"`
	AdditionalMsg string   `json:"am,omitempty"`
	Show          string   `json:"-"`
	Nuclei        string   `json:"nuclei,omitempty"`
}

// ToString 将输出结构转换为人类可读的文本展示
// 根据不同的事件类型（IPAlive/PortScan/Web/Finger/Nuclei 等）
// 生成带颜色标签的中文格式化输出。
// 返回值：格式化的展示字符串和可能的错误（未知类型时返回错误）
func (o *OutputMessage) ToString() (string, error) {
	r := ""
	var err error

	// IP存活验证
	if o.Type == "IPAlive" {
		r = "[存活] " + o.IP
	} else if o.Type == "PortScan" {
		r = "[端口扫描] " + o.IP + ":" + o.Port
	} else if o.Type == "Nmap" {
		r = fmt.Sprintf("[Nmap] %s://%s:%s", o.Protocol, o.IP, o.Port)
	} else if o.Type == "Web" {
		// 将“网页”标签着色为 MEDIUM 的黄色
		r = fmt.Sprintf("[%s] [%v] %s", aurora.Yellow("网页").String(), o.Web.Status, o.URI)
		if o.Web.Title != "" {
			r += " [" + o.Web.Title + "]"
		}
	} else if o.Type == "DNS-Brute" {
		r = "[字典爆破] " + o.Domain
	} else if o.Type == "CDN-Domain" {
		r = "[CDN域名] " + o.Domain
	} else if o.Type == "RealIP" {
		r = "[真实IP] " + o.Domain + " => "
		for _, v := range o.IPs {
			r += v + ","
		}
		r = r[:len(r)-1]
	} else if o.Type == "Finger" {
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

		// 将“被动指纹”标签着色为 CRITICAL 的红色（仅更改展示名称）
		r = fmt.Sprintf("[%s] %s ", aurora.Red("被动指纹").String(), o.URI)
		if o.Web.Status != "" {
			r += fmt.Sprintf("[%s] ", o.Web.Status)
		}
		r += "["
		for _, c := range o.Finger {
			r += aurora.Red(c).String() + ","
		}
		r = r[:len(r)-1] + "]"
		if o.Web.Title != "" {
			r += fmt.Sprintf(" [%s]", o.Web.Title)
		}
	} else if o.Type == "Active-Finger" {
		// 将“主动指纹”标签着色为 CRITICAL 的红色
		r = fmt.Sprintf("[%s] %s [", aurora.Red("主动指纹").String(), o.URI)
		for _, c := range o.Finger {
			r += aurora.Red(c).String() + ","
		}
		r = r[:len(r)-1] + "]"
	} else if o.Type == "Domain-Bind" {
		r = "[域名绑定] [" + o.Web.Status + "] " + o.URI
	} else if o.Type == "Hunter" {
		r = "[Hunter] "
		if o.URI == "" {
			r += o.Protocol + "://" + o.IP + ":" + o.Port
		} else {
			r += fmt.Sprintf("[%v] %s [%s] [%s]", o.Web.Status, o.URI, o.Web.Title, o.City)
		}
	} else if o.Type == "Fofa" {
		r = o.Show
	} else if o.Type == "Quake" {
		r = "[Quake] " + o.Show
	} else if o.Type == "Nuclei" {
		// o.Show 形如: "[templateID] [Severity] matchedURL"
		tpl := ""
		sev := ""
		matched := ""

		show := o.Show
		// 提取中括号内的字段
		tokens := []string{}
		rest := show
		for {
			i := strings.Index(rest, "[")
			if i == -1 {
				break
			}
			j := strings.Index(rest[i+1:], "]")
			if j == -1 {
				break
			}
			token := rest[i+1 : i+1+j]
			tokens = append(tokens, token)
			rest = rest[i+1+j+1:]
		}
		if len(tokens) >= 1 {
			tpl = tokens[0]
		}
		if len(tokens) >= 2 {
			sev = tokens[1]
		}
		matched = strings.TrimSpace(rest)

		// 显示颜色：模板ID使用与 Golang 引擎一致的红色
		tplStr := aurora.Red(tpl).String()
		sevLower := strings.ToLower(sev)
		sevShow := sev
		switch sevLower {
		case "critical":
			// 红色 #FF0000
			sevShow = rgbColor(sev, 255, 0, 0)
		case "high":
			// 橙色 #FFA500
			sevShow = rgbColor(sev, 255, 165, 0)
		case "medium":
			// 黄色 #FFD700（金色）
			sevShow = rgbColor(sev, 255, 215, 0)
		case "low":
			// 绿色 #00FF00
			sevShow = rgbColor(sev, 0, 255, 0)
		case "info":
			// 蓝色 #1E90FF（亮蓝）
			sevShow = rgbColor(sev, 30, 144, 255)
		default:
			// 灰色 #808080
			sevShow = rgbColor(sev, 128, 128, 128)
		}
		// 漏洞地址改为白色：去除颜色渲染，保持终端默认颜色（白色）
		matchStr := matched
		r = fmt.Sprintf("[Nuclei] [%s] [%s] %s", tplStr, sevShow, matchStr)
	} else {
		err = fmt.Errorf("error OutputMessage Type: %s", o.Type)
	}

	if err == nil && o.AdditionalMsg != "" {
		r += " [" + o.AdditionalMsg + "]"
	}

	return r, err
}

// ToJson 将输出结构序列化为 JSON 字符串
// 返回值：JSON 字符串和可能的错误
func (o *OutputMessage) ToJson() (string, error) {
	b, err := json.Marshal(o)
	return string(b), err
}

// writeFile 将结果追加写入输出文件
// 参数：result - 要写入的文本行
// 文件以追加模式（O_APPEND）打开，确保多次调用不覆盖已有内容
func writeFile(result string) {
	filename := OutputFileName

	var text = []byte(result + "\n")
	fl, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		return
	}
	_, err = fl.Write(text)
	fl.Close()
	if err != nil {
		fmt.Printf("Write %s error, %v\n", filename, err)
	}
}

// FormatOutput 根据配置输出到控制台或文件
// 参数：o - 要输出的消息结构
// 功能：
// - 始终打印到控制台（通过 gologger.Silent()）
// - 如果配置了输出文件，则根据 OutputType（text/json）写入文件
// - text 模式会去除 ANSI 颜色码后写入
// - 跳过被动指纹（Finger）类型，避免日志过于冗长
func FormatOutput(o OutputMessage) {
	// 跳过被动指纹的输出，避免日志过于冗长。
	if o.Type == "Finger" {
		return
	}

	// 先格式化为字符串
	s, err := o.ToString()
	if err != nil {
		return
	}
	// 始终打印到控制台，包括 Nuclei 结果
	if s != "" {
		gologger.Silent().Msg(s)
	}
	// 若未配置输出文件，仅打印到控制台
	if OutputFileName == "" || s == "" {
		return
	}
	if OutputType == "text" {
		// 去掉所有 ANSI 颜色代码，确保写入纯文本
		ansiRegex := regexp.MustCompile("\x1b\\[[0-9;]*m")
		s = ansiRegex.ReplaceAllString(s, "")
		writeFile(s)
	} else if OutputType == "json" {
		j, e := o.ToJson()
		if e == nil {
			writeFile(j)
		}
	}

}

// rgbColor 以 24 位真彩色（True Color）渲染文本
// 参数：
//   - s: 要渲染的字符串
//   - r, g, b: RGB 颜色分量（0-255）
//
// 返回值：包含 ANSI 24 位颜色控制码的字符串（需要终端支持 truecolor）
//
// 使用场景：为不同严重等级的漏洞结果赋予不同的颜色（红/橙/黄/绿/蓝/灰）
func rgbColor(s string, r, g, b int) string {
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s\x1b[0m", r, g, b, s)
}
