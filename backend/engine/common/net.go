// ========================================
// 包 common: 网络连接封装模块（Network Connection Wrapper）
//
// 功能概述：
//
//	对 Go 标准库的 net.Dial 进行封装，提供带有超时控制和自定义 Dialer 的
//	TCP 连接建立能力。这些封装函数被端口扫描模块调用，用于探测目标端口是否开放。
//
// 设计思路：
//   - WrapperTcpWithTimeout：便捷的超时封装，只需传入超时时间
//   - WrapperTCP：接受外部 Dialer 的灵活封装，可自定义代理、本地地址等
//
// 集成关系：
//   - 被 portscan.go 的 PortConnect 函数调用，用于端口连通性探测
//   - 可扩展支持通过代理进行端口扫描（通过传入自定义 Dialer）
//
// ========================================
package common

import (
	"net"
	"time"
)

// WrapperTcpWithTimeout 使用自定义超时创建 TCP 连接
//
// 功能说明：
//
//	创建一个带有超时限制的 TCP 连接。内部构造一个设定了 Timeout 的 net.Dialer，
//	然后委托给 WrapperTCP 完成实际的连接建立。
//
// 参数：
//   - network: 网络类型，通常为 "tcp4" 或 "tcp"
//   - address: 目标地址，格式为 "host:port"
//   - timeout: 连接超时时间
//
// 返回值：
//   - net.Conn: 成功建立的 TCP 连接
//   - error: 连接失败时返回错误信息
//
// 使用场景：
//   - 端口扫描中对单个 IP:Port 进行 TCP 连通性探测
//   - 每个端口探测通常设置 1-5 秒的超时
func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return WrapperTCP(network, address, d)
}

// WrapperTCP 通过外部传入的 Dialer 建立连接
//
// 功能说明：
//
//	使用传入的 net.Dialer 建立网络连接。外部可通过自定义 Dialer 实现
//	代理转发、本地地址绑定、KeepAlive 设置等高级功能。
//
// 参数：
//   - network: 网络类型（如 "tcp4"）
//   - address: 目标地址（格式如 "192.168.1.1:80"）
//   - forward: 已配置好的 net.Dialer 指针（可设置超时、代理等）
//
// 返回值：
//   - net.Conn: 成功建立的连接
//   - error: 连接失败时的错误，包括超时、拒绝连接等
//
// 注意事项：
//   - 调用方负责关闭返回的 net.Conn
//   - forward 参数为 nil 时将使用默认 Dialer
func WrapperTCP(network, address string, forward *net.Dialer) (net.Conn, error) {
	// 使用传入的 Dialer 建立连接
	var conn net.Conn
	var err error
	conn, err = forward.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return conn, nil

}
