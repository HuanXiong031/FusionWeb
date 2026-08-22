// 包 utils: 输入解析与常用工具函数
// 该文件提供各种输入格式校验（IP/域名/URL/端口等），以及去重、文件校验等实用方法。
//
// 支持的输入格式：
// - IPv4/IPv6 地址
// - CIDR 网段（如 192.168.0.0/24）
// - IP 范围（如 192.168.0.1-192.168.0.255）
// - 域名（支持多级域名和多种顶级域）
// - URL（http://example.com/path）
// - 端口号（1-65535）
// - 组合格式：IP:Port / Domain:Port / Host:Port/Path
//
// GetInputType 函数自动识别输入类型并返回对应枚举值，是整个扫描引擎的入口分类器
package utils

import (
	"FusionWeb/backend/core/structs"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// IsIPv4 IsIP checks if a string is either IP version 4 Alias for `net.ParseIP`
// IsIPv4 判断字符串是否为 IPv4 地址
func IsIPv4(str string) bool {
	for i := 0; i < len(str); i++ {
		if str[i] == '.' {
			return net.ParseIP(str) != nil
		}
	}
	return false
}

// IsIPv6 IsIP checks if a string is either IP version 4 Alias for `net.ParseIP`
// IsIPv6 判断字符串是否为 IPv6 地址
func IsIPv6(str string) bool {
	for i := 0; i < len(str); i++ {
		if str[i] == ':' {
			return net.ParseIP(str) != nil
		}
	}
	return false
}

// IsCIDR checks if the string is an valid CIDR notation (IPV4)
// IsCIDR 判断字符串是否为合法 IPv4 CIDR 表达式
func IsCIDR(str string) bool {
	_, _, err := net.ParseCIDR(str)
	return err == nil
}

// IsIPPort 判断字符串是否为 "IP:Port" 格式
func IsIPPort(str string) bool {
	if !strings.Contains(str, ":") {
		return false
	}
	t := strings.Split(str, ":")
	if len(t) != 2 {
		return false
	}
	if !IsIPv4(t[0]) {
		return false
	}
	if !IsPort(t[1]) {
		return false
	}
	return true
}

// IsPort checks if a string represents a valid port
// IsPort 判断字符串是否为合法端口（1-65535）
func IsPort(str string) bool {
	if i, err := strconv.Atoi(str); err == nil && i > 0 && i < 65536 {
		return true
	}
	return false
}

var (
	domainRootString = `[a-z]{2,5}`
	domainRegx       = regexp.MustCompile(`^([a-zA-Z0-9][-a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})*\.(?:` + domainRootString + `))$`)
)

// stringContainsCTLByte 检查字符串是否包含 ASCII 控制字符
// 参数：s - 要检查的字符串
// 返回值：true 表示包含控制字符（ASCII < 32 或 == 0x7F）
// 控制字符的存在通常意味着非法输入，需要拦截
func stringContainsCTLByte(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < ' ' || b == 0x7f {
			return true
		}
	}
	return false
}

// IsDomain 判断字符串是否为合法域名
func IsDomain(str string) bool {
	if stringContainsCTLByte(str) == true {
		return false
	}
	if ok := domainRegx.MatchString(str); ok == false {
		return false
	}
	return true
}

// IsDomainPort checks if a string is Domain:Port
// IsDomainPort 判断字符串是否为 "Domain:Port" 格式
func IsDomainPort(str string) bool {
	r := strings.Split(str, ":")
	if len(r) != 2 {
		return false
	}
	domain := r[0]
	port := r[1]
	return IsDomain(domain) && IsPort(port)
}

// IsIPRange 判断字符串是否为 "IPv4-IPv4" 范围表达式
func IsIPRange(str string) bool {
	r := strings.Split(str, "-")
	return (len(r) == 2) && IsIPv4(strings.TrimSpace(r[0])) && IsIPv4(strings.TrimSpace(r[1]))
}

// IsProtocol 判断协议名是否符合约束（1-20 位大小写字母/数字/连字符）
func IsProtocol(str string) bool {
	ok, _ := regexp.MatchString("^[-a-z0-9A-Z]{1,20}$", str)
	return ok
}

// IsNetloc 判断是否为 Domain 或 IPv4
func IsNetloc(str string) bool {
	return IsDomain(str) || IsIPv4(str)
}

// IsNetlocPort checks if a string is [Domain or IP]:Port
// IsNetlocPort 判断是否为 "Domain|IP:Port" 格式
func IsNetlocPort(str string) bool {
	r := strings.Split(str, ":")
	if len(r) != 2 {
		return false
	}
	netloc := r[0]
	port := r[1]
	return IsNetloc(netloc) && IsPort(port)
}

// IsHostPath checks if a string is :
// netloc/path
// netloc:port/path
// IsHostPath 判断是否为 "netloc/path" 或 "netloc:port/path" 格式
func IsHostPath(str string) bool {
	index := strings.Index(str, "/")
	if index == -1 {
		return false
	}
	str = str[:index]
	if strings.Contains(str, ":") == true {
		return IsNetlocPort(str)
	} else {
		return IsNetloc(str)

	}
}

// IsURL checks if a string is :
// protocol://netloc/path
// protocol://netloc:port/path
// IsURL 判断是否为合法 URL，如 "http://example.com/path"
func IsURL(str string) bool {
	if stringContainsCTLByte(str) == true {
		return false
	}
	index := strings.Index(str, "://")
	if index == -1 {
		return false
	}
	protocol := str[:index]
	if IsProtocol(protocol) == false {
		return false
	}
	str = str[index+3:]
	if IsNetloc(str) {
		return true
	}
	if IsNetlocPort(str) {
		return true
	}
	if IsHostPath(str) {
		return true
	}
	return false
}

// RemoveDuplicateElement 对字符串切片去重
// 参数：input - 可能包含重复值的字符串切片
// 返回值：去重后的切片，保持元素首次出现的相对顺序
// 使用 map 实现 O(n) 时间复杂度
func RemoveDuplicateElement(input []string) []string {
	temp := map[string]struct{}{}
	var result []string
	for _, item := range input {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// RemoveDuplicateElementInt 对整数切片去重并保持相对顺序
func RemoveDuplicateElementInt(input []int) []int {
	temp := map[int]struct{}{}
	var result []int
	for _, item := range input {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// IsFileNameValid 判断文件是否存在
func IsFileNameValid(name string) bool {
	_, err := os.Stat(name)
	if err == nil {
		return true
	}
	return false
}

// GetInputType 返回输入类型枚举（Domain/IP/CIDR/URL 等），用于前置分类
func GetInputType(input string) int {
	if IsIPv6(input) {
		return structs.TypeUnSupport
	} else if IsIPv4(input) {
		return structs.TypeIP
	} else if IsIPRange(input) {
		return structs.TypeIPRange
	} else if IsCIDR(input) {
		return structs.TypeCIDR
	} else if IsIPPort(input) {
		return structs.TypeIPPort
	} else if IsDomainPort(input) {
		return structs.TypeDomainPort
	} else if IsDomain(input) {
		return structs.TypeDomain
	} else if IsURL(input) {
		return structs.TypeURL
	}

	return structs.TypeUnSupport
}

// GetItemInArray 返回字符串在切片中的索引，未找到返回 -1
func GetItemInArray(a []string, s string) int {
	for index, v := range a {
		if v == s {
			return index
		}
	}
	return -1
}

// DeleteReportWithNoResult 删除无实质结果的报告文件
// 基于文件大小的简单判定：小于 99360 字节（约 97KB）的报告视为无实质结果
// 自动删除以释放磁盘空间，避免累积空报告
func DeleteReportWithNoResult() {
	fileInfo, err := os.Stat(structs.GlobalConfig.ReportName)
	if err == nil {
		fileSize := fileInfo.Size()
		// 简单粗暴判断文件大小
		if fileSize < 99360 {
			_ = os.Remove(structs.GlobalConfig.ReportName)
		}
	}
}
