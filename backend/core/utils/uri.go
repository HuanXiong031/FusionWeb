// backend/core/utils/uri.go
// IP 地址与 URL 解析工具模块
// 提供 IP 范围计算、CIDR 展开、HTTP 响应解析等底层工具函数。
// 设计要点：
// - CIDR 转 IP 列表：支持将 CIDR 表达式展开为完整的 IP 列表
// - IP 范围解析：支持多种范围格式（192.168.0.1-192.168.2.255 等）
// - HTTP 响应解析：从原始 HTTP 响应中提取状态码、头、正文、Server 等字段
// - IPv4 专用：本模块主要处理 IPv4 地址，IPv6 需额外处理
package utils

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"
)

// FirstIP 获取 IP 网络的第一个 IP 地址（网络地址）
// 参数：network - IP 网络对象
// 返回值：网络的第一个 IP 地址
func FirstIP(network *net.IPNet) net.IP {
	return network.IP
}

// toIP 将 32 位无符号整数转换为 IPv4 点分十进制字符串
// 参数：i - 32 位整数表示的 IP 地址
// 返回值：如 "192.168.1.1"
func toIP(i uint32) string {
	buf := bytes.NewBuffer([]byte{})
	_ = binary.Write(buf, binary.BigEndian, i)
	b := buf.Bytes()
	return fmt.Sprintf("%v.%v.%v.%v", b[0], b[1], b[2], b[3])
}

// toInt 将 IP 地址转换为 32 位无符号整数表示
// 参数：ip - net.IP 对象（支持 IPv4，IPv6 只取后 4 字节）
// 返回值：32 位整数表示的 IP 地址
// 用于 IP 范围计算时的数值比较
func toInt(ip net.IP) uint32 {
	var buf = []byte(ip)
	if len(buf) > 12 {
		buf = buf[12:]
	}
	buffer := bytes.NewBuffer(buf)
	var i uint32
	_ = binary.Read(buffer, binary.BigEndian, &i)
	return i
}

// pairsToIP 将一对 IP 地址展开为范围内的所有 IP
// 参数：ip1 - 起始 IP，ip2 - 结束 IP
// 返回值：从 ip1 到 ip2（含）的所有 IP 地址切片
func pairsToIP(ip1, ip2 net.IP) (IPs []net.IP) {
	start := toInt(ip1)
	end := toInt(ip2)
	for i := start; i <= end; i++ {
		IPs = append(IPs, net.ParseIP(toIP(i)))
	}
	return IPs
}

// LastIP 获取 IP 网络的最后一个 IP 地址（广播地址）
// 参数：network - IP 网络对象
// 返回值：网络的最后一个 IP 地址
func LastIP(network *net.IPNet) net.IP {
	firstIP := FirstIP(network)
	mask, _ := network.Mask.Size()
	size := math.Pow(2, float64(32-mask))
	lastIP := toIP(toInt(firstIP) + uint32(size) - 1)
	return net.ParseIP(lastIP)
}

// CIDRToIP 将 CIDR 表达式展开为完整的 IP 列表
// 参数：cidr - CIDR 格式字符串（如 "192.168.0.0/24"）
// 返回值：该网段内所有 IP 地址的切片
func CIDRToIP(cidr string) (IPs []net.IP) {
	_, network, _ := net.ParseCIDR(cidr)
	first := FirstIP(network)
	last := LastIP(network)
	return pairsToIP(first, last)
}

// parseIPPairs 解析 IP 范围表达式为起止 IP
// 支持多种简写格式：
//   - 192.168.0.1-192.168.2.255（完整格式）
//   - 192.168.0.1-255（简写：只写最后一段）
//   - 192.168.0.1-2.255（简写：只写最后两段）
// 参数：str - IP 范围字符串
// 返回值：起始 IP 和结束 IP，解析失败返回 nil
func parseIPPairs(str string) (ip1 net.IP, ip2 net.IP) {
	if strings.Count(str, "-") != 1 {
		return nil, nil
	}
	r := strings.Split(str, "-")
	s1 := r[0]
	s2 := r[1]
	if ip1 = net.ParseIP(s1); ip1 == nil {
		return nil, nil
	}
	i := strings.Count(s2, ".")
	if i > 3 {
		return ip1, nil
	}
	rs1 := strings.Split(s1, ".")
	rs2 := strings.Join(append(rs1[:3-i], s2), ".")
	ip2 = net.ParseIP(rs2)
	if ip2 == nil {
		return ip1, nil
	}
	if toInt(ip1) >= toInt(ip2) {
		return nil, nil
	}
	return ip1, ip2
}

// RangerToIP 将 IP 范围表达式展开为完整的 IP 列表
// 参数：ranger - IP 范围字符串（如 "192.168.0.1-192.168.0.10"）
// 返回值：该范围内所有 IP 地址的切片
func RangerToIP(ranger string) (IPs []net.IP) {
	first, last := parseIPPairs(ranger)
	return pairsToIP(first, last)
}

// IsLocalIP 判断 IP 地址是否为局域网地址或回环地址
// 参数：input - IP 地址字符串
// 返回值：true 表示私有地址（10.x, 172.16-31.x, 192.168.x）或回环地址（127.x）
func IsLocalIP(input string) bool {
	ip := net.ParseIP(input)
	return ip.IsPrivate() || ip.IsLoopback()
}

// ExtractResponse 从原始 HTTP 响应字符串中提取各组成部分
// 参数：response - 原始 HTTP 响应文本（以 "HTTP" 开头）
// 返回值（按顺序）：
//   - code: HTTP 状态码（如 "200"）
//   - header: 响应头部分
//   - body: 响应体部分
//   - server: Server 头字段值
//   - contentType: Content-Type 头字段值
//   - contentLen: Content-Length 头字段值
//
// 解析流程：HTTP 状态行 → 拆分为 Headers 和 Body → 提取特定头字段
// 输入不以 "HTTP" 开头时返回空字符串（非 HTTP 响应）
func ExtractResponse(response string) (code string, header string, body string, server string, contentType string, contentLen string) {
	if !strings.HasPrefix(response, "HTTP") {
		return "", "", "", "", "", ""
	}
	parts := strings.SplitN(response, "\r\n", 2)
	if len(parts) != 2 {
		return "", "", "", "", "", ""
	}
	responseLine := parts[0]
	remaining := parts[1]

	headerParts := strings.SplitN(remaining, "\r\n\r\n", 2)
	if len(headerParts) != 2 {
		return "", "", "", "", "", ""
	}
	header = headerParts[0]
	body = headerParts[1]

	server = ""
	t := strings.Split(header, "\r\n")
	if strings.Contains(strings.ToLower(header), "server: ") {
		for _, line := range t {
			if !strings.HasPrefix(strings.ToLower(line), "server: ") {
				continue
			}
			tt := strings.SplitN(line, ": ", 2)
			server = tt[1]
		}
	}

	contentType = ""
	if strings.Contains(strings.ToLower(header), "content-type: ") {
		for _, line := range t {
			if !strings.HasPrefix(strings.ToLower(line), "content-type: ") {
				continue
			}
			tt := strings.SplitN(line, ": ", 2)
			contentType = tt[1]
		}
	}

	contentLen = ""
	if strings.Contains(strings.ToLower(header), "content-length: ") {
		for _, line := range t {
			if !strings.HasPrefix(strings.ToLower(line), "content-length: ") {
				continue
			}
			tt := strings.SplitN(line, ": ", 2)
			contentLen = tt[1]
		}
	}

	responseCode := strings.Fields(responseLine)[1]
	return responseCode, header, body, server, contentType, contentLen
}
