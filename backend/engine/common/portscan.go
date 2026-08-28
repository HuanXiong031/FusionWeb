// Package common provides FusionWeb's port service scanner.
//
// The current scanner intentionally uses a dependency-light TCP connect probe for
// port discovery, then reuses gonmap to produce qscan-style protocol, service and
// banner fields for each open port.
package common

import (
	"FusionWeb/backend/core/ddout"
	"FusionWeb/backend/core/structs"
	"FusionWeb/backend/core/utils"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/lcvvvv/gonmap"
	"github.com/projectdiscovery/gologger"
)

// ParsePort parses a port expression such as "80,443,8000-8100".
func ParsePort(ports string) (scanPorts []int) {
	if ports == "" {
		return
	}
	seen := make(map[int]struct{})
	for _, item := range strings.Split(ports, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		startText, endText := item, item
		if strings.Contains(item, "-") {
			parts := strings.SplitN(item, "-", 2)
			if len(parts) != 2 {
				continue
			}
			startText = strings.TrimSpace(parts[0])
			endText = strings.TrimSpace(parts[1])
		}

		start, err1 := strconv.Atoi(startText)
		end, err2 := strconv.Atoi(endText)
		if err1 != nil || err2 != nil {
			continue
		}
		if start > end {
			start, end = end, start
		}
		for port := start; port <= end; port++ {
			if port < 1 || port > 65535 {
				continue
			}
			if _, ok := seen[port]; ok {
				continue
			}
			seen[port] = struct{}{}
			scanPorts = append(scanPorts, port)
		}
	}
	return scanPorts
}

// Addr describes a host/port probe target.
type Addr struct {
	ip   string
	port int
}

// PortServiceResult is the unified result produced by the new port service scanner.
type PortServiceResult struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Address        string `json:"address"`
	Status         string `json:"status"`
	Protocol       string `json:"protocol"`
	Service        string `json:"service"`
	GuessedService string `json:"guessed_service,omitempty"`
	Product        string `json:"product,omitempty"`
	Version        string `json:"version,omitempty"`
	Info           string `json:"info,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	OS             string `json:"os,omitempty"`
	Device         string `json:"device,omitempty"`
	ProbeName      string `json:"probe_name,omitempty"`
	TLS            bool   `json:"tls,omitempty"`
	Banner         string `json:"banner,omitempty"`
}

// PortServiceScanOptions configures the unified scanner.
type PortServiceScanOptions struct {
	Ports            string
	NoPorts          string
	TimeoutSeconds   int
	Threads          int
	PortsThreshold   int
	Random           bool
	DetectService    bool
	DeepIdentify     bool
	EmitOutput       bool
	ResultCallback   func(PortServiceResult)
	ProgressCallback func(done, total int)
}

// ScanPortServices scans hosts using the configured port expression and returns
// open ports with structured protocol/service/banner metadata.
func ScanPortServices(hosts []string, options PortServiceScanOptions) []PortServiceResult {
	ports := filteredPorts(ParsePort(options.Ports), ParsePort(options.NoPorts))
	hosts = normalizeScanHosts(hosts)
	if len(hosts) == 0 || len(ports) == 0 {
		return nil
	}

	if options.Random {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		rng.Shuffle(len(hosts), func(i, j int) {
			hosts[i], hosts[j] = hosts[j], hosts[i]
		})
		rng.Shuffle(len(ports), func(i, j int) {
			ports[i], ports[j] = ports[j], ports[i]
		})
	}

	total := multiplyTaskCount(len(hosts), len(ports))
	return scanPortTaskStream(total, options, func(jobs chan<- Addr) {
		for _, port := range ports {
			for _, host := range hosts {
				jobs <- Addr{ip: host, port: port}
			}
		}
	})
}

// ScanPortServiceTargets scans explicit host:port targets.
func ScanPortServiceTargets(targets []string, options PortServiceScanOptions) []PortServiceResult {
	if len(targets) == 0 {
		return nil
	}

	tasks := normalizeExplicitPortTargets(targets)
	if len(tasks) == 0 {
		return nil
	}

	if options.Random {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		rng.Shuffle(len(tasks), func(i, j int) {
			tasks[i], tasks[j] = tasks[j], tasks[i]
		})
	}

	return scanPortTaskStream(len(tasks), options, func(jobs chan<- Addr) {
		for _, task := range tasks {
			jobs <- task
		}
	})
}

func scanPortTaskStream(total int, options PortServiceScanOptions, enqueue func(chan<- Addr)) []PortServiceResult {
	if total <= 0 || enqueue == nil {
		return nil
	}
	if options.TimeoutSeconds <= 0 {
		options.TimeoutSeconds = 3
	}
	options.Threads = normalizePortScanThreads(options.Threads, total, getOpenFileLimit())
	if options.PortsThreshold <= 0 {
		options.PortsThreshold = structs.GlobalConfig.PortsThreshold
	}
	if options.PortsThreshold <= 0 {
		options.PortsThreshold = 65535
	}

	gologger.AuditTimeLogger("开始端口服务扫描，目标数: %d，并发: %d", total, options.Threads)

	jobs := make(chan Addr, options.Threads)
	results := make(chan PortServiceResult, options.Threads)
	var workers sync.WaitGroup

	openCount := make(map[string]int)
	blacklist := make(map[string]struct{})
	var stateMu sync.Mutex
	completed := 0
	var progressMu sync.Mutex

	isBlacklisted := func(host string) bool {
		stateMu.Lock()
		defer stateMu.Unlock()
		_, ok := blacklist[host]
		return ok
	}

	recordOpen := func(host string) bool {
		stateMu.Lock()
		defer stateMu.Unlock()
		if _, ok := blacklist[host]; ok {
			return false
		}
		openCount[host]++
		if openCount[host] > options.PortsThreshold {
			blacklist[host] = struct{}{}
			gologger.Error().Msgf("%s 开放端口数量超过阈值 %d，停止记录该主机", host, options.PortsThreshold)
			return false
		}
		return true
	}

	markProgress := func() {
		progressMu.Lock()
		completed++
		done := completed
		progressMu.Unlock()
		if options.ProgressCallback != nil {
			options.ProgressCallback(done, total)
		}
	}

	for i := 0; i < options.Threads; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range jobs {
				if isBlacklisted(task.ip) {
					markProgress()
					continue
				}

				if !isPortOpen(task.ip, task.port, options.TimeoutSeconds) {
					markProgress()
					continue
				}
				if !recordOpen(task.ip) {
					markProgress()
					continue
				}

				result := PortServiceResult{
					Host:           task.ip,
					Port:           task.port,
					Address:        net.JoinHostPort(task.ip, strconv.Itoa(task.port)),
					Status:         "open",
					Protocol:       "tcp",
					GuessedService: GuessPortService(task.port),
				}
				if options.DetectService {
					result = identifyPortService(result, options.TimeoutSeconds, options.DeepIdentify)
				}

				if options.ResultCallback != nil {
					options.ResultCallback(result)
				}
				results <- result
				markProgress()
			}
		}()
	}

	go func() {
		enqueue(jobs)
		close(jobs)
		workers.Wait()
		close(results)
	}()

	collected := make([]PortServiceResult, 0)
	for result := range results {
		collected = append(collected, result)
	}

	sortPortServiceResults(collected)

	gologger.AuditTimeLogger("端口服务扫描结束，开放端口: %d", len(collected))
	return collected
}

func normalizePortScanThreads(requested, total, fdLimit int) int {
	const (
		defaultThreads     = 100
		maxSafeThreads     = 512
		fileReserveThreads = 128
		minSafeThreads     = 16
	)

	if requested <= 0 {
		requested = defaultThreads
	}
	if total > 0 && requested > total {
		requested = total
	}
	if requested > maxSafeThreads {
		gologger.Warning().Msgf("端口扫描并发从 %d 下调到 %d，避免占满程序连接资源", requested, maxSafeThreads)
		requested = maxSafeThreads
	}
	if fdLimit > 0 {
		fdCap := fdLimit - fileReserveThreads
		if fdCap < minSafeThreads {
			fdCap = minSafeThreads
		}
		if requested > fdCap {
			gologger.Warning().Msgf("端口扫描并发从 %d 下调到 %d，避免超过文件描述符上限 %d", requested, fdCap, fdLimit)
			requested = fdCap
		}
	}
	if requested <= 0 {
		return 1
	}
	return requested
}

func filteredPorts(ports, noPorts []int) []int {
	if len(noPorts) == 0 {
		return ports
	}
	excluded := make(map[int]struct{}, len(noPorts))
	for _, port := range noPorts {
		excluded[port] = struct{}{}
	}
	filtered := make([]int, 0, len(ports))
	for _, port := range ports {
		if _, ok := excluded[port]; ok {
			continue
		}
		filtered = append(filtered, port)
	}
	return filtered
}

func normalizeScanHosts(hosts []string) []string {
	if len(hosts) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

func normalizeExplicitPortTargets(targets []string) []Addr {
	if len(targets) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(targets))
	out := make([]Addr, 0, len(targets))
	for _, target := range targets {
		host, port, ok := splitHostPort(target)
		if !ok {
			continue
		}
		key := net.JoinHostPort(host, strconv.Itoa(port))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Addr{ip: host, port: port})
	}
	return out
}

func multiplyTaskCount(a, b int) int {
	if a <= 0 || b <= 0 {
		return 0
	}
	maxInt := int(^uint(0) >> 1)
	if a > maxInt/b {
		return maxInt
	}
	return a * b
}

func isPortOpen(host string, port int, timeoutSeconds int) bool {
	conn, err := WrapperTcpWithTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), time.Duration(timeoutSeconds)*time.Second)
	if conn != nil {
		_ = conn.Close()
	}
	return err == nil
}

func identifyPortService(result PortServiceResult, timeoutSeconds int, deep bool) PortServiceResult {
	scanner := gonmap.New()
	scanner.SetTimeout(time.Duration(timeoutSeconds) * time.Second)
	if deep {
		scanner.OpenDeepIdentify()
	}

	status, response := scanner.ScanTimeout(result.Host, result.Port, time.Duration(timeoutSeconds)*time.Second)
	if status == gonmap.Closed || response == nil {
		return identifyHTTPFallback(result, timeoutSeconds)
	}

	if response.Raw != "" {
		result.Banner = cleanBanner(response.Raw)
	}
	result.TLS = response.TLS

	if response.FingerPrint == nil || response.FingerPrint.Service == "" {
		return identifyHTTPFallback(result, timeoutSeconds)
	}

	finger := response.FingerPrint
	protocol := normalizeProtocol(finger.Service)
	if protocol != "" {
		result.Protocol = protocol
	}
	result.Product = strings.TrimSpace(finger.ProductName)
	result.Version = strings.TrimSpace(finger.Version)
	result.Info = strings.TrimSpace(finger.Info)
	result.Hostname = strings.TrimSpace(finger.Hostname)
	result.OS = strings.TrimSpace(finger.OperatingSystem)
	result.Device = strings.TrimSpace(finger.DeviceType)
	result.ProbeName = strings.TrimSpace(finger.ProbeName)
	result.Service = serviceSummary(result)
	if result.Protocol == "tcp" {
		return identifyHTTPFallback(result, timeoutSeconds)
	}
	return result
}

func identifyHTTPFallback(result PortServiceResult, timeoutSeconds int) PortServiceResult {
	if normalizeProtocol(result.Protocol) != "tcp" {
		return result
	}
	timeout := httpProbeTimeout(timeoutSeconds)
	if result.TLS || isLikelyHTTPSPort(result.Port) {
		if banner, ok := probeHTTPService(result.Host, result.Port, "https", timeout); ok {
			return applyHTTPFallback(result, "https", banner)
		}
	}
	if banner, ok := probeHTTPService(result.Host, result.Port, "http", timeout); ok {
		return applyHTTPFallback(result, "http", banner)
	}
	return result
}

func applyHTTPFallback(result PortServiceResult, protocol, banner string) PortServiceResult {
	result.Protocol = protocol
	if protocol == "https" {
		result.TLS = true
	}
	if result.Service == "" || strings.EqualFold(result.Service, "tcp") {
		result.Service = strings.ToUpper(protocol)
	}
	if banner != "" && result.Banner == "" {
		result.Banner = banner
	}
	return result
}

func probeHTTPService(host string, port int, protocol string, timeout time.Duration) (string, bool) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if protocol == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			ServerName:         tlsServerName(host),
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		return "", false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: FusionWeb-PortProbe\r\nAccept: */*\r\nConnection: close\r\n\r\n", httpHostHeader(host, port))
	if _, err := conn.Write([]byte(request)); err != nil {
		return "", false
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if n <= 0 || err != nil {
		return "", false
	}
	response := string(buf[:n])
	if !isHTTPResponse(response) {
		return "", false
	}
	return httpResponseFirstLine(response), true
}

func httpProbeTimeout(timeoutSeconds int) time.Duration {
	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeout <= 0 || timeout > 1500*time.Millisecond {
		return 1500 * time.Millisecond
	}
	if timeout < 300*time.Millisecond {
		return 300 * time.Millisecond
	}
	return timeout
}

func isLikelyHTTPSPort(port int) bool {
	switch port {
	case 443, 8443, 9443, 10443:
		return true
	default:
		return false
	}
}

func tlsServerName(host string) string {
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return ""
	}
	return strings.Trim(host, "[]")
}

func httpHostHeader(host string, port int) string {
	host = strings.Trim(host, "[]")
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func isHTTPResponse(response string) bool {
	response = strings.TrimLeft(response, "\r\n")
	return strings.HasPrefix(response, "HTTP/")
}

func httpResponseFirstLine(response string) string {
	response = strings.TrimLeft(response, "\r\n")
	if idx := strings.IndexAny(response, "\r\n"); idx >= 0 {
		response = response[:idx]
	}
	return cleanBanner(response)
}

func normalizeProtocol(protocol string) string {
	protocol = strings.TrimSpace(protocol)
	if protocol == "" || strings.EqualFold(protocol, "unknown") {
		return "tcp"
	}
	protocol = gonmap.FixProtocol(protocol)
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" || protocol == "unknown" {
		return "tcp"
	}
	return protocol
}

func GuessPortService(port int) string {
	return commonPortServices[port]
}

func serviceSummary(result PortServiceResult) string {
	parts := make([]string, 0, 4)
	if result.Product != "" {
		parts = append(parts, result.Product)
	}
	if result.Version != "" {
		parts = append(parts, result.Version)
	}
	if result.Info != "" {
		parts = append(parts, result.Info)
	}
	if len(parts) == 0 {
		if result.Service != "" {
			return result.Service
		}
		return result.Protocol
	}
	return strings.Join(parts, " ")
}

func cleanBanner(raw string) string {
	if raw == "" {
		return ""
	}
	if !utf8.ValidString(raw) {
		raw = strings.ToValidUTF8(raw, "?")
	}
	raw = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		if r < 32 {
			return ' '
		}
		return r
	}, raw)
	raw = strings.TrimSpace(raw)
	const maxBannerLength = 4096
	if len(raw) > maxBannerLength {
		raw = raw[:maxBannerLength] + "..."
	}
	return raw
}

func emitPortOutput(result PortServiceResult) {
	ddout.FormatOutput(ddout.OutputMessage{
		Type:     "PortScan",
		IP:       result.Host,
		Port:     strconv.Itoa(result.Port),
		Protocol: result.Protocol,
	})
}

func sortPortServiceResults(results []PortServiceResult) {
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Host == results[j].Host {
			return results[i].Port < results[j].Port
		}
		return results[i].Host < results[j].Host
	})
}

func splitHostPort(target string) (string, int, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, false
	}
	if host, portText, err := net.SplitHostPort(target); err == nil {
		port, err := strconv.Atoi(portText)
		return strings.Trim(host, "[]"), port, err == nil && port >= 1 && port <= 65535
	}
	idx := strings.LastIndex(target, ":")
	if idx <= 0 || idx >= len(target)-1 {
		return "", 0, false
	}
	host := strings.TrimSpace(strings.Trim(target[:idx], "[]"))
	port, err := strconv.Atoi(strings.TrimSpace(target[idx+1:]))
	if err != nil || host == "" || port < 1 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

// RemoveFirewall is retained for legacy callers that still operate on host:port strings.
func RemoveFirewall(ipPorts []string) []string {
	if len(ipPorts) == 0 {
		return nil
	}
	threshold := structs.GlobalConfig.PortsThreshold
	if threshold <= 0 {
		threshold = 65536
	}

	byHost := make(map[string][]string)
	for _, target := range ipPorts {
		host, _, ok := splitHostPort(target)
		if !ok {
			continue
		}
		byHost[host] = append(byHost[host], target)
	}

	filtered := make([]string, 0, len(ipPorts))
	for host, targets := range byHost {
		ports := make(map[string]struct{})
		for _, target := range targets {
			_, port, ok := splitHostPort(target)
			if ok {
				ports[strconv.Itoa(port)] = struct{}{}
			}
		}
		if len(ports) >= threshold {
			gologger.Error().Msgf("%s 端口数量超出阈值,已丢弃", host)
			continue
		}
		filtered = append(filtered, targets...)
	}
	return utils.RemoveDuplicateElement(filtered)
}

var commonPortServices = map[int]string{
	20:    "ftp-data",
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	67:    "dhcp",
	68:    "dhcp",
	69:    "tftp",
	80:    "http",
	81:    "http",
	88:    "kerberos",
	110:   "pop3",
	111:   "rpcbind",
	119:   "nntp",
	123:   "ntp",
	135:   "rpc",
	137:   "netbios",
	138:   "netbios",
	139:   "netbios",
	143:   "imap",
	161:   "snmp",
	162:   "snmptrap",
	389:   "ldap",
	443:   "https",
	445:   "smb",
	465:   "smtps",
	500:   "ike",
	514:   "syslog",
	587:   "smtp",
	636:   "ldaps",
	873:   "rsync",
	993:   "imaps",
	995:   "pop3s",
	1080:  "socks",
	1433:  "mssql",
	1521:  "oracle",
	1723:  "pptp",
	2049:  "nfs",
	2181:  "zookeeper",
	2375:  "docker",
	2376:  "docker-tls",
	3128:  "http-proxy",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5672:  "amqp",
	5900:  "vnc",
	5984:  "couchdb",
	5985:  "winrm",
	5986:  "winrm-ssl",
	6379:  "redis",
	7001:  "weblogic",
	8000:  "http",
	8009:  "ajp",
	8080:  "http",
	8081:  "http",
	8443:  "https",
	9000:  "http",
	9092:  "kafka",
	9200:  "elasticsearch",
	9300:  "elasticsearch",
	11211: "memcached",
	15672: "rabbitmq",
	27017: "mongodb",
	27018: "mongodb",
	50000: "db2",
	50070: "hdfs",
}

func addressFromHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (r PortServiceResult) HostPort() string {
	if r.Address != "" {
		return r.Address
	}
	return addressFromHostPort(r.Host, r.Port)
}

func (r PortServiceResult) String() string {
	return fmt.Sprintf("%s %s %s", r.HostPort(), r.Protocol, r.Service)
}
