// ========================================
// 包 common: 主机存活探测模块（Host Alive Detection via ICMP/Ping）
//
// 功能概述：
//
//	对目标 IP 列表进行存活探测，支持三种探测方式，按优先级自动选择：
//	1. 本地监听 ICMP 批量探测（RunIcmp1）：监听原始 ICMP Socket，批量发包并接收响应
//	2. 无监听 ICMP 探测（RunIcmp2）：逐目标 Dial ICMP Socket，并发执行
//	3. 系统命令 Ping 探测（RunPing）：跨平台（Windows/Linux/macOS）调用系统 ping 命令
//
// 探测策略：
//   - 默认优先尝试本地监听 ICMP（需 root/管理员权限）
//   - 失败则降级为无监听 ICMP 探测
//   - 再失败则降级为系统 ping 命令
//   - 可强制使用 ping 模式（Ping=true）
//
// 输出：
//   - 命令行只输出存活数量汇总，避免逐个 IP 刷屏
//   - 存活主机列表通过 AliveHosts 全局变量返回
//
// 全局变量：
//   - AliveHosts：所有存活的 IP 列表
//   - ExistHosts：已确认存活的主机集合（用于去重）
//   - OS：当前操作系统类型（windows/linux/darwin）
//
// 集成关系：
//   - 由扫描引擎主流程调用，是资产发现的第一步
//   - 输出结果供后续端口扫描（portscan.go）使用
//   - 返回存活结果供后续端口扫描（portscan.go）使用
//
// ========================================
package common

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/icmp"
)

var (
	// AliveHosts 存储所有探测确认存活的主机 IP 地址列表
	// 由 CheckLive 函数填充，供后续端口扫描等模块使用
	AliveHosts []string
	// OS 当前运行平台的操作系统类型（windows/linux/darwin）
	// 用于决定 ping 命令的参数格式
	OS = runtime.GOOS
	// ExistHosts 已确认存活的主机 IP 集合（使用空结构体 map 节省内存）
	// 用于防止同一个 IP 被重复添加到 AliveHosts 中
	ExistHosts = make(map[string]struct{})
	// livewg 存活探测的全局 WaitGroup
	// 用于等待所有探测协程完成后才返回结果
	livewg  sync.WaitGroup
	aliveMu sync.Mutex
)

// ResetAliveState 重置存活探测的全局状态
// 在每次新的存活探测开始前调用，清空上一次探测的结果
func ResetAliveState() {
	aliveMu.Lock()
	defer aliveMu.Unlock()
	AliveHosts = make([]string, 0)
	ExistHosts = make(map[string]struct{})
}

// IsContain 判断字符串切片中是否包含指定的字符串
//
// 参数：
//   - items: 要搜索的字符串切片
//   - item: 要查找的目标字符串
//
// 返回值：如果切片包含该字符串则返回 true，否则返回 false
func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

// CheckLive 对输入的 IP 列表进行存活探测
//
// 功能说明：
//
//	接收 IP 列表，通过 ICMP 或系统 Ping 进行存活探测，返回所有存活的 IP 地址。
//	结果只在结束时汇总输出存活数量，避免逐个 IP 刷屏。
//
// 探测策略（三级降级）：
//  1. 若 Ping=true：直接使用系统 Ping 命令
//  2. 否则优先尝试本地监听 ICMP 批量探测（RunIcmp1，效率最高）
//  3. 若失败，尝试无监听 ICMP 探测（RunIcmp2）
//  4. 若再失败，降级为系统 Ping 命令（RunPing）
//
// 参数：
//   - hostslist: 待探测的目标 IP 地址列表
//   - Ping: 是否强制使用 Ping 模式（true=强制 Ping，false=自动选择）
//
// 返回值：
//   - []string: 所有确认存活的主机 IP 地址列表
//
// 并发与同步：
//   - 使用缓冲通道 chanHosts 收集存活结果
//   - 使用 livewg.WaitGroup 等待所有探测完成
func CheckLive(hostslist []string, Ping bool) []string {
	chanHosts := make(chan string, len(hostslist))
	go func() {
		for ip := range chanHosts {
			if _, ok := ExistHosts[ip]; !ok && IsContain(hostslist, ip) {
				ExistHosts[ip] = struct{}{}
				AliveHosts = append(AliveHosts, ip)
			}
			livewg.Done()
		}
	}()

	if Ping == true {
		//使用ping探测
		RunPing(hostslist, chanHosts)
	} else {
		//优先尝试监听本地icmp,批量探测
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err == nil {
			RunIcmp1(hostslist, conn, chanHosts)
		} else {
			//尝试无监听icmp探测
			conn, err := net.DialTimeout("ip4:icmp", "127.0.0.1", 6*time.Second)
			defer func() {
				if conn != nil {
					conn.Close()
				}
			}()
			if err == nil {
				RunIcmp2(hostslist, chanHosts)
			} else {
				gologger.Error().Msgf("尝试ICMP探测失败，转为Ping探测存活")
				//使用ping探测
				RunPing(hostslist, chanHosts)
			}
		}
	}

	livewg.Wait()
	close(chanHosts)
	gologger.Info().Msgf("存活探测完成，发现 %d 个存活主机", len(AliveHosts))

	return AliveHosts
}

// RunIcmp1 使用本地监听的 ICMP Socket 进行批量探测
//
// 功能说明：
//
//	通过 icmp.ListenPacket 创建的原始 ICMP Socket 进行批量主机存活探测。
//	此方式需要 root/管理员权限才能创建原始 Socket。
//	批量发送 ICMP Echo 请求后，通过监听 Socket 接收所有的 ICMP Echo Reply。
//
// 工作流程：
//  1. 启动后台协程持续监听 ICMP Reply 报文
//  2. 收到 Reply 后，将源 IP 通过 chanHosts 发送给结果收集协程
//  3. 遍历 hostslist，对每个目标构造并发送 ICMP Echo Request
//  4. 根据目标数量设置等待超时（≤256 目标等 3 秒，>256 等 6 秒）
//  5. 超时后关闭连接，结束探测
//
// 参数：
//   - hostslist: 目标 IP 列表
//   - conn: 已建立的 ICMP PacketConn 连接
//   - chanHosts: 存活结果的通道（缓冲通道，防止阻塞）
//
// 注意事项：
//   - 需要 root/管理员权限
//   - 原始 ICMP Socket 比无监听模式效率更高（单 Socket 收发）
//   - 等待时间根据目标数量动态调整，避免遗漏响应
func RunIcmp1(hostslist []string, conn *icmp.PacketConn, chanHosts chan string) {
	endflag := false
	go func() {
		for {
			if endflag == true {
				return
			}
			msg := make([]byte, 100)
			_, sourceIP, _ := conn.ReadFrom(msg)
			if sourceIP != nil {
				livewg.Add(1)
				chanHosts <- sourceIP.String()
			}
		}
	}()

	for _, host := range hostslist {
		dst, _ := net.ResolveIPAddr("ip", host)
		IcmpByte := makemsg(host)
		conn.WriteTo(IcmpByte, dst)
	}
	//根据hosts数量修改icmp监听时间
	start := time.Now()
	for {
		if len(AliveHosts) == len(hostslist) {
			break
		}
		since := time.Now().Sub(start)
		var wait time.Duration
		switch {
		case len(hostslist) <= 256:
			wait = time.Second * 3
		default:
			wait = time.Second * 6
		}
		if since > wait {
			break
		}
	}
	endflag = true
	conn.Close()
}

// RunIcmp2 使用无监听的 ICMP 探测方式（逐目标 Dial），并发执行
//
// 功能说明：
//
//	当无法创建原始 ICMP Socket（无 root 权限）时，此方式作为降级方案。
//	对每个目标单独调用 net.DialTimeout，建立 ICMP 连接并收发数据包。
//	使用协程+信号量控制并发数（最多 1000 个并发）。
//
// 参数：
//   - hostslist: 目标 IP 列表
//   - chanHosts: 存活结果的通道
//
// 并发控制：
//   - 使用 limiter 通道控制同时探测的协程数
//   - 每个目标启动一个协程独立探测
//   - icmpalive 函数设定 6 秒超时
func RunIcmp2(hostslist []string, chanHosts chan string) {
	num := 1000
	if len(hostslist) < num {
		num = len(hostslist)
	}
	var wg sync.WaitGroup
	limiter := make(chan struct{}, num)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if icmpalive(host) {
				livewg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
	close(limiter)
}

// icmpalive 针对单个目标进行 ICMP 探测
//
// 功能说明：
//
//	使用 net.DialTimeout 建立到目标 IP 的 ICMP 连接（"ip4:icmp"协议），
//	发送构造的 ICMP Echo Request 报文并等待 Response。
//	任何步骤出错都返回 false。
//
// 参数：
//   - host: 目标 IP 地址
//
// 返回值：
//   - true: ICMP 探测成功，目标存活
//   - false: 探测失败（超时/拒绝/网络不可达等）
//
// 超时设置：
//   - 连接超时：6 秒
//   - 读写超时：连接建立后额外 6 秒
func icmpalive(host string) bool {
	startTime := time.Now()
	conn, err := net.DialTimeout("ip4:icmp", host, 6*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return false
	}
	if err := conn.SetDeadline(startTime.Add(6 * time.Second)); err != nil {
		return false
	}
	msg := makemsg(host)
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	receive := make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}

	return true
}

// RunPing 使用系统命令（Windows/Linux/macOS）对目标进行 ping 探测
//
// 功能说明：
//
//	当 ICMP Socket 探测不可用时，降级使用操作系统自带的 ping 命令。
//	这是最通用的探测方式，但效率最低（每个目标需要启动一个子进程）。
//
// 跨平台适配：
//   - Windows: 使用 cmd shell
//   - Linux/macOS: 使用 /bin/bash shell
//   - 各平台的 ping 命令参数通过 ExecCommandPing 处理
//
// 参数：
//   - hostslist: 目标 IP 列表
//   - chanHosts: 存活结果的通道
//
// 并发控制：
//   - 最多 50 个并发协程同时执行 ping 命令
func RunPing(hostslist []string, chanHosts chan string) {
	var bsenv = ""
	if OS != "windows" {
		bsenv = "/bin/bash"
	}
	var wg sync.WaitGroup
	limiter := make(chan struct{}, 50)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if ExecCommandPing(host, bsenv) {
				livewg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
}

// ExecCommandPing 执行具体的 ping 命令并判断结果，跨平台适配
//
// 功能说明：
//
//	根据操作系统类型选择对应的 ping 命令参数，执行系统 ping 并判断是否成功。
//
// 跨平台参数：
//   - Windows: "ping -n 1 -w 1000 <ip>"  （发送 1 个包，超时 1000ms）
//   - Linux:   "ping -c 1 -W 1 <ip>"     （发送 1 个包，超时 1s）
//   - macOS:   "ping -c 1 -W 1 <ip>"     （同 Linux）
//
// 参数：
//   - ip: 目标 IP 地址
//   - bsenv: Shell 环境（Windows 为空，Linux/macOS 为 "/bin/bash"）
//
// 返回值：
//   - true: ping 成功，目标存活
//   - false: ping 失败或操作系统不支持
func ExecCommandPing(ip string, bsenv string) bool {
	var command *exec.Cmd
	if OS == "windows" {
		command = exec.Command("ping", "-n", "1", "-w", "1000", ip)
	} else if OS == "linux" {
		command = exec.Command("ping", "-c", "1", "-W", "1", ip)
	} else if OS == "darwin" {
		command = exec.Command("ping", "-c", "1", "-W", "1", ip)
	} else {
		return false
	}

	err := command.Run()
	return err == nil
}

// makemsg 构造 ICMP Echo 请求报文
//
// 功能说明：
//
//	构造一个标准的 ICMP Echo Request（Type 8, Code 0）报文：
//	- 字节 0-1:  类型=8（Echo Request），代码=0
//	- 字节 2-3:  校验和（由 checkSum 计算填充）
//	- 字节 4-5:  标识符（基于目标 IP 生成）
//	- 字节 6-7:  序列号（固定为 1）
//	- 字节 8-39: 数据负载（全零）
//
// 参数：
//   - host: 目标 IP 地址，用于生成报文标识符
//
// 返回值：
//   - 40 字节的 ICMP Echo Request 报文
func makemsg(host string) []byte {
	msg := make([]byte, 40)
	id0, id1 := genIdentifier(host)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4], msg[5] = id0, id1
	msg[6], msg[7] = genSequence(1)
	check := checkSum(msg[0:40])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 255)
	return msg
}

// checkSum 计算 ICMP 报文校验和
//
// 功能说明：
//
//	采用标准的互联网校验和算法（RFC 1071）：
//	1. 将报文按 16 位字（2 字节）分组求和
//	2. 若报文长度为奇数，最后一个字节左移 8 位后加入
//	3. 将高 16 位溢出加到低 16 位（进位折叠）
//	4. 取反码作为最终校验值
//
// 参数：
//   - msg: 待计算校验和的 ICMP 报文字节切片
//
// 返回值：
//   - 计算得到的 16 位校验和
func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	answer := uint16(^sum)
	return answer
}

// genSequence 将 16 位整数拆分为高 8 位和低 8 位
//
// 用于构造 ICMP 报文中的序列号字段。
//
// 参数：
//   - v: 16 位有符号整数
//
// 返回值：
//   - byte, byte: 高位字节和低位字节
func genSequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)
	ret2 := byte(v & 255)
	return ret1, ret2
}

// genIdentifier 从目标 IP 字符串的前两个字节生成标识符
//
// 用于 ICMP 报文的标识符字段，基于目标 IP 地址生成，便于区分不同的目标。
//
// 参数：
//   - host: 目标 IP 地址字符串
//
// 返回值：
//   - byte, byte: IP 地址的前两个字节，作为报文标识符
func genIdentifier(host string) (byte, byte) {
	return host[0], host[1]
}

// ArrayCountValueTop 统计 IP 段（B段或C段）的出现频率，返回出现次数最多的网段
//
// 功能说明：
//
//	将 IP 地址列表按 B 段（flag=true, X.X）或 C 段（flag=false, X.X.X）聚合，
//	统计每个网段出现的次数，按出现频率降序排序，返回前 length 个高频网段。
//
// 参数：
//   - arrInit: 待统计的 IP 地址列表
//   - length: 返回的网段数量上限
//   - flag: true 按 B 段统计（前两段），false 按 C 段统计（前三段）
//
// 返回值：
//   - arrTop: 出现频率最高的网段列表（按频率降序）
//   - arrLen: 对应网段的出现次数
//
// 使用场景：
//   - 端口扫描结果分析：识别哪些 IP 段开放端口最多
//   - 辅助判断是否存在防火墙/CDN 等安全设备
func ArrayCountValueTop(arrInit []string, length int, flag bool) (arrTop []string, arrLen []int) {
	if len(arrInit) == 0 {
		return
	}
	arrMap1 := make(map[string]int)
	arrMap2 := make(map[string]int)
	for _, value := range arrInit {
		line := strings.Split(value, ".")
		if len(line) == 4 {
			if flag {
				value = fmt.Sprintf("%s.%s", line[0], line[1])
			} else {
				value = fmt.Sprintf("%s.%s.%s", line[0], line[1], line[2])
			}
		}
		if arrMap1[value] != 0 {
			arrMap1[value]++
		} else {
			arrMap1[value] = 1
		}
	}
	for k, v := range arrMap1 {
		arrMap2[k] = v
	}

	i := 0
	for _ = range arrMap1 {
		var maxCountKey string
		var maxCountVal = 0
		for key, val := range arrMap2 {
			if val > maxCountVal {
				maxCountVal = val
				maxCountKey = key
			}
		}
		arrTop = append(arrTop, maxCountKey)
		arrLen = append(arrLen, maxCountVal)
		i++
		if i >= length {
			return
		}
		delete(arrMap2, maxCountKey)
	}
	return
}
