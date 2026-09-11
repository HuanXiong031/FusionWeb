package cli

import (
	"FusionWeb/backend/engine/common"
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PortScanOptions struct {
	Tool              string
	Hosts             []string
	ExplicitTargets   []string
	Ports             string
	NoPorts           string
	Rate              int
	TimeoutSeconds    int
	Threads           int
	Retries           int
	ScanType          string
	PortsThreshold    int
	SkipHostDiscovery bool
	IdentifyService   bool
	Logf              LogFunc
}

type hostScanSpec struct {
	Host  string
	Ports string
}

func RunPortScan(ctx context.Context, options PortScanOptions) ([]common.PortServiceResult, error) {
	tool := normalizeToolName(options.Tool)
	if tool == "" {
		tool = normalizeToolName(os.Getenv("FUSIONWEB_PORT_SCAN_TOOL"))
	}
	if tool == "" {
		tool = "naabu"
	}

	specs := buildHostScanSpecs(options.Hosts, options.ExplicitTargets, options.Ports, options.NoPorts)
	if len(specs) == 0 {
		return nil, nil
	}

	var (
		results []common.PortServiceResult
		err     error
	)
	switch tool {
	case "naabu":
		results, err = runNaabuPortScan(ctx, specs, options)
	case "masscan":
		results, err = runMasscanPortScan(ctx, specs, options)
	case "nmap":
		results, err = runNmapPortScan(ctx, specs, options)
	default:
		return nil, fmt.Errorf("不支持的端口扫描 CLI 工具: %s", tool)
	}
	if err != nil {
		return nil, err
	}

	results = dedupePortResults(results)
	// nmap 作为主扫描器时已在同一次调用里做了 -sV，无需再跑一遍服务识别
	if options.IdentifyService && serviceIdentifyEnabled() && tool != "nmap" && len(results) > 0 {
		results, err = identifyPortServicesWithNmap(ctx, results, options)
		if err != nil {
			return nil, err
		}
	}
	return dedupePortResults(results), nil
}

func buildHostScanSpecs(hosts, explicitTargets []string, ports, noPorts string) []hostScanSpec {
	hosts = dedupeStrings(hosts)
	globalPorts := filteredPortExpression(ports, noPorts)
	noPortSet := intSet(common.ParsePort(noPorts))

	hostPortMap := make(map[string]map[int]struct{})
	for _, target := range explicitTargets {
		host, port, ok := splitHostPortTarget(target)
		if !ok || port <= 0 {
			continue
		}
		if _, excluded := noPortSet[port]; excluded {
			continue
		}
		if hostPortMap[host] == nil {
			hostPortMap[host] = make(map[int]struct{})
		}
		hostPortMap[host][port] = struct{}{}
	}

	specs := make([]hostScanSpec, 0, len(hosts)+len(hostPortMap))
	seenHost := make(map[string]struct{})
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		seenHost[host] = struct{}{}
		specPorts := globalPorts
		if len(hostPortMap[host]) > 0 {
			specPorts = mergePortExpression(specPorts, hostPortMap[host])
		}
		if strings.TrimSpace(specPorts) != "" {
			specs = append(specs, hostScanSpec{Host: host, Ports: specPorts})
		}
	}

	for host, portSet := range hostPortMap {
		if _, ok := seenHost[host]; ok {
			continue
		}
		portExpr := formatPortSet(portSet)
		if portExpr != "" {
			specs = append(specs, hostScanSpec{Host: host, Ports: portExpr})
		}
	}

	sort.Slice(specs, func(i, j int) bool {
		if specs[i].Host == specs[j].Host {
			return specs[i].Ports < specs[j].Ports
		}
		return specs[i].Host < specs[j].Host
	})
	return specs
}

func runNaabuPortScan(ctx context.Context, specs []hostScanSpec, options PortScanOptions) ([]common.PortServiceResult, error) {
	if _, err := ResolveTool("naabu"); err != nil {
		return nil, err
	}

	processes := cliProcessConcurrency(len(specs))
	resultsCh := make(chan []common.PortServiceResult, len(specs))
	errCh := make(chan error, len(specs))
	jobs := make(chan hostScanSpec)
	var wg sync.WaitGroup

	for i := 0; i < processes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for spec := range jobs {
				results, err := scanNaabuHost(ctx, spec, options)
				if err != nil {
					errCh <- err
					continue
				}
				resultsCh <- results
			}
		}()
	}

dispatch:
	for _, spec := range specs {
		select {
		case <-ctx.Done():
			break dispatch
		case jobs <- spec:
		}
	}
	close(jobs)
	wg.Wait()
	close(resultsCh)
	close(errCh)

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(errCh) > 0 {
		return nil, <-errCh
	}

	var results []common.PortServiceResult
	for batch := range resultsCh {
		results = append(results, batch...)
	}
	return results, nil
}

func scanNaabuHost(ctx context.Context, spec hostScanSpec, options PortScanOptions) ([]common.PortServiceResult, error) {
	args := []string{
		"-host", spec.Host,
		"-json",
		"-silent",
		"-rate", strconv.Itoa(defaultInt(options.Rate, 3000)),
		"-timeout", strconv.Itoa(defaultInt(options.TimeoutSeconds, 3)),
		"-retries", strconv.Itoa(defaultInt(options.Retries, 2)),
		"-warm-up-time", "1",
		"-c", strconv.Itoa(defaultInt(options.Threads, 50)),
		"-Pn",
	}

	switch strings.ToLower(strings.TrimSpace(spec.Ports)) {
	case "top100":
		args = append(args, "-tp", "100")
	case "top1000":
		args = append(args, "-tp", "1000")
	default:
		args = append(args, "-p", spec.Ports)
	}

	scanType := strings.ToLower(strings.TrimSpace(options.ScanType))
	if scanType == "" {
		scanType = strings.ToLower(strings.TrimSpace(os.Getenv("FUSIONWEB_NAABU_SCAN_TYPE")))
	}
	if scanType == "s" || scanType == "syn" {
		args = append(args, "-s")
	}
	if options.PortsThreshold > 0 {
		args = append(args, "-port-threshold", strconv.Itoa(options.PortsThreshold))
	}

	timeout := time.Duration(defaultInt(options.TimeoutSeconds, 3)+30) * time.Second
	result, err := Execute(ctx, "naabu", args, ExecuteOptions{Timeout: timeout, Logf: options.Logf})
	if err != nil {
		return nil, err
	}
	return parseNaabuOutput(strings.NewReader(result.Stdout), spec.Host), nil
}

func runMasscanPortScan(ctx context.Context, specs []hostScanSpec, options PortScanOptions) ([]common.PortServiceResult, error) {
	if _, err := ResolveTool("masscan"); err != nil {
		return nil, err
	}

	groups := make(map[string][]string)
	for _, spec := range specs {
		groups[spec.Ports] = append(groups[spec.Ports], spec.Host)
	}

	var results []common.PortServiceResult
	for ports, hosts := range groups {
		args := []string{
			"-p", ports,
			"--rate", strconv.Itoa(defaultInt(options.Rate, 1000)),
			"-oJ", "-",
		}
		if options.SkipHostDiscovery {
			args = append(args, "-Pn")
		}
		args = append(args, hosts...)

		timeout := time.Duration(defaultInt(options.TimeoutSeconds, 3)+30) * time.Second
		result, err := Execute(ctx, "masscan", args, ExecuteOptions{Timeout: timeout, Logf: options.Logf})
		if err != nil {
			return nil, err
		}
		results = append(results, parseMasscanOutput(strings.NewReader(result.Stdout))...)
	}
	return results, nil
}

type naabuResult struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	TLS      bool   `json:"tls"`
}

func parseNaabuOutput(scannerInput *strings.Reader, fallbackHost string) []common.PortServiceResult {
	var results []common.PortServiceResult
	scanner := bufio.NewScanner(scannerInput)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var item naabuResult
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue
		}
		if item.Port <= 0 {
			continue
		}
		host := firstNonEmpty(item.Host, fallbackHost, item.IP)
		if net.ParseIP(fallbackHost) == nil && fallbackHost != "" {
			host = fallbackHost
		}
		protocol := strings.TrimSpace(item.Protocol)
		if protocol == "" {
			protocol = "tcp"
		}
		results = append(results, common.PortServiceResult{
			Host:           host,
			Port:           item.Port,
			Address:        net.JoinHostPort(host, strconv.Itoa(item.Port)),
			Status:         "open",
			Protocol:       protocol,
			Service:        protocol,
			GuessedService: common.GuessPortService(item.Port),
			TLS:            item.TLS,
		})
	}
	return results
}

type masscanResult struct {
	IP    string `json:"ip"`
	Ports []struct {
		Port   int    `json:"port"`
		Proto  string `json:"proto"`
		Status string `json:"status"`
	} `json:"ports"`
}

func parseMasscanOutput(scannerInput *strings.Reader) []common.PortServiceResult {
	var results []common.PortServiceResult
	scanner := bufio.NewScanner(scannerInput)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimSuffix(line, ",")
		if line == "" || line == "[" || line == "]" || !strings.HasPrefix(line, "{") {
			continue
		}
		var item masscanResult
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue
		}
		for _, port := range item.Ports {
			if port.Port <= 0 || strings.ToLower(port.Status) != "open" {
				continue
			}
			protocol := strings.TrimSpace(port.Proto)
			if protocol == "" {
				protocol = "tcp"
			}
			results = append(results, common.PortServiceResult{
				Host:           item.IP,
				Port:           port.Port,
				Address:        net.JoinHostPort(item.IP, strconv.Itoa(port.Port)),
				Status:         "open",
				Protocol:       protocol,
				Service:        protocol,
				GuessedService: common.GuessPortService(port.Port),
			})
		}
	}
	return results
}

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Ports nmapPorts `xml:"ports"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name       string `xml:"name,attr"`
	Product    string `xml:"product,attr"`
	Version    string `xml:"version,attr"`
	ExtraInfo  string `xml:"extrainfo,attr"`
	Hostname   string `xml:"hostname,attr"`
	OSType     string `xml:"ostype,attr"`
	DeviceType string `xml:"devicetype,attr"`
	Tunnel     string `xml:"tunnel,attr"`
}

func identifyPortServicesWithNmap(ctx context.Context, results []common.PortServiceResult, options PortScanOptions) ([]common.PortServiceResult, error) {
	if _, err := ResolveTool("nmap"); err != nil {
		return nil, fmt.Errorf("端口服务识别需要 nmap: %w", err)
	}

	grouped := make(map[string]map[int]struct{})
	for _, result := range results {
		if result.Host == "" || result.Port <= 0 {
			continue
		}
		if grouped[result.Host] == nil {
			grouped[result.Host] = make(map[int]struct{})
		}
		grouped[result.Host][result.Port] = struct{}{}
	}

	type nmapJob struct {
		host  string
		ports string
	}
	jobs := make([]nmapJob, 0, len(grouped))
	for host, ports := range grouped {
		jobs = append(jobs, nmapJob{host: host, ports: formatPortSet(ports)})
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].host < jobs[j].host })

	updates := make(chan []common.PortServiceResult, len(jobs))
	jobCh := make(chan nmapJob)
	var wg sync.WaitGroup
	processes := cliProcessConcurrency(len(jobs))
	for i := 0; i < processes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				identified := scanNmapHost(ctx, job.host, job.ports, options)
				if len(identified) > 0 {
					updates <- identified
				}
			}
		}()
	}
dispatch:
	for _, job := range jobs {
		select {
		case <-ctx.Done():
			break dispatch
		case jobCh <- job:
		}
	}
	close(jobCh)
	wg.Wait()
	close(updates)

	byKey := make(map[string]common.PortServiceResult, len(results))
	for _, result := range results {
		byKey[result.HostPort()] = result
	}
	for batch := range updates {
		for _, result := range batch {
			byKey[result.HostPort()] = result
		}
	}

	merged := make([]common.PortServiceResult, 0, len(byKey))
	for _, result := range byKey {
		merged = append(merged, result)
	}
	sortPortResults(merged)
	return merged, nil
}

func scanNmapHost(ctx context.Context, host, ports string, options PortScanOptions) []common.PortServiceResult {
	if strings.TrimSpace(ports) == "" {
		return nil
	}

	args := []string{
		"-Pn",
		"-sV",
		"--version-intensity", "5",
		"-p", ports,
		"-oX", "-",
		host,
	}
	timeout := time.Duration(defaultInt(options.TimeoutSeconds, 30)+30) * time.Second
	result, err := Execute(ctx, "nmap", args, ExecuteOptions{Timeout: timeout, Logf: options.Logf})
	if err != nil {
		if options.Logf != nil {
			options.Logf("WARN", "nmap 服务识别失败 %s:%s: %v", host, ports, err)
		}
		return nil
	}

	var parsed nmapRun
	if err := xml.Unmarshal([]byte(result.Stdout), &parsed); err != nil {
		if options.Logf != nil {
			options.Logf("WARN", "nmap XML 解析失败 %s:%s: %v", host, ports, err)
		}
		return nil
	}
	return parseNmapRunResults(host, parsed)
}

// parseNmapRunResults 把 nmap XML 结果转换成统一端口结果（服务识别与 nmap 主扫描共用）。
func parseNmapRunResults(host string, parsed nmapRun) []common.PortServiceResult {
	var results []common.PortServiceResult
	for _, h := range parsed.Hosts {
		for _, p := range h.Ports.Ports {
			if strings.ToLower(p.State.State) != "open" || p.PortID <= 0 {
				continue
			}
			service := strings.TrimSpace(p.Service.Name)
			protocol := service
			if protocol == "" {
				protocol = strings.TrimSpace(p.Protocol)
			}
			if protocol == "" {
				protocol = "tcp"
			}
			if p.Service.Tunnel == "ssl" && service == "http" {
				protocol = "https"
			}
			results = append(results, common.PortServiceResult{
				Host:           host,
				Port:           p.PortID,
				Address:        net.JoinHostPort(host, strconv.Itoa(p.PortID)),
				Status:         "open",
				Protocol:       protocol,
				Service:        service,
				GuessedService: common.GuessPortService(p.PortID),
				Product:        p.Service.Product,
				Version:        p.Service.Version,
				Info:           p.Service.ExtraInfo,
				Hostname:       p.Service.Hostname,
				OS:             p.Service.OSType,
				Device:         p.Service.DeviceType,
				TLS:            p.Service.Tunnel == "ssl",
			})
		}
	}
	return results
}

// runNmapPortScan 直接以 nmap 作为端口发现工具（-Pn -p <端口/范围>，支持 top100/top1000 预设）。
// 开启服务识别时在同一次调用里带 -sV，避免"发现 + 识别"跑两遍 nmap。
func runNmapPortScan(ctx context.Context, specs []hostScanSpec, options PortScanOptions) ([]common.PortServiceResult, error) {
	if _, err := ResolveTool("nmap"); err != nil {
		return nil, err
	}

	results := make([]common.PortServiceResult, 0)
	for _, spec := range specs {
		ports := strings.TrimSpace(spec.Ports)
		if ports == "" {
			continue
		}

		args := []string{"-Pn"}
		switch strings.ToLower(ports) {
		case "top100":
			args = append(args, "--top-ports", "100")
		case "top1000":
			args = append(args, "--top-ports", "1000")
		default:
			args = append(args, "-p", ports)
		}
		if options.IdentifyService {
			args = append(args, "-sV", "--version-intensity", "5")
		}
		args = append(args, "-oX", "-", spec.Host)

		timeout := time.Duration(defaultInt(options.TimeoutSeconds, 30)+120) * time.Second
		if options.Logf != nil {
			options.Logf("INFO", "[CLI] nmap %s", strings.Join(args, " "))
		}
		result, err := Execute(ctx, "nmap", args, ExecuteOptions{Timeout: timeout, Logf: options.Logf})
		if err != nil {
			// 单个目标失败不应中断整批扫描
			if options.Logf != nil {
				options.Logf("WARN", "nmap 扫描失败 %s: %v", spec.Host, err)
			}
			continue
		}

		var parsed nmapRun
		if err := xml.Unmarshal([]byte(result.Stdout), &parsed); err != nil {
			if options.Logf != nil {
				options.Logf("WARN", "nmap XML 解析失败 %s: %v", spec.Host, err)
			}
			continue
		}
		results = append(results, parseNmapRunResults(spec.Host, parsed)...)
	}
	return results, nil
}

func splitHostPortTarget(target string) (string, int, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, false
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		if strings.Count(target, ":") != 1 {
			return "", 0, false
		}
		parts := strings.SplitN(target, ":", 2)
		host, portText = parts[0], parts[1]
	}
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	host = strings.Trim(host, "[] ")
	if host == "" {
		return "", 0, false
	}
	return host, port, true
}

func filteredPortExpression(ports, noPorts string) string {
	ports = strings.TrimSpace(ports)
	if ports == "" {
		return ""
	}
	excluded := intSet(common.ParsePort(noPorts))
	if len(excluded) == 0 {
		return ports
	}
	parsed := common.ParsePort(ports)
	if len(parsed) == 0 {
		return ports
	}
	out := make(map[int]struct{}, len(parsed))
	for _, port := range parsed {
		if _, skip := excluded[port]; !skip {
			out[port] = struct{}{}
		}
	}
	return formatPortSet(out)
}

func mergePortExpression(expr string, extra map[int]struct{}) string {
	parsed := common.ParsePort(expr)
	if len(parsed) == 0 {
		if strings.TrimSpace(expr) != "" {
			return expr
		}
		return formatPortSet(extra)
	}
	merged := intSet(parsed)
	for port := range extra {
		merged[port] = struct{}{}
	}
	return formatPortSet(merged)
}

func intSet(items []int) map[int]struct{} {
	out := make(map[int]struct{}, len(items))
	for _, item := range items {
		if item > 0 {
			out[item] = struct{}{}
		}
	}
	return out
}

func formatPortSet(portSet map[int]struct{}) string {
	if len(portSet) == 0 {
		return ""
	}
	ports := make([]int, 0, len(portSet))
	for port := range portSet {
		if port >= 1 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	if len(ports) == 0 {
		return ""
	}

	parts := make([]string, 0)
	start := ports[0]
	prev := ports[0]
	flush := func() {
		if start == prev {
			parts = append(parts, strconv.Itoa(start))
			return
		}
		parts = append(parts, fmt.Sprintf("%d-%d", start, prev))
	}
	for _, port := range ports[1:] {
		if port == prev+1 {
			prev = port
			continue
		}
		flush()
		start = port
		prev = port
	}
	flush()
	return strings.Join(parts, ",")
}

func dedupePortResults(results []common.PortServiceResult) []common.PortServiceResult {
	byKey := make(map[string]common.PortServiceResult, len(results))
	for _, result := range results {
		if result.Host == "" || result.Port <= 0 {
			continue
		}
		if result.Address == "" {
			result.Address = net.JoinHostPort(result.Host, strconv.Itoa(result.Port))
		}
		if result.Status == "" {
			result.Status = "open"
		}
		if result.Protocol == "" {
			result.Protocol = "tcp"
		}
		if result.GuessedService == "" {
			result.GuessedService = common.GuessPortService(result.Port)
		}
		key := result.HostPort()
		if existing, ok := byKey[key]; ok && portResultScore(existing) >= portResultScore(result) {
			continue
		}
		byKey[key] = result
	}
	out := make([]common.PortServiceResult, 0, len(byKey))
	for _, result := range byKey {
		out = append(out, result)
	}
	sortPortResults(out)
	return out
}

func portResultScore(result common.PortServiceResult) int {
	score := 0
	for _, value := range []string{result.Protocol, result.Service, result.Product, result.Version, result.Info, result.Banner} {
		if strings.TrimSpace(value) != "" && strings.TrimSpace(value) != "tcp" {
			score++
		}
	}
	return score
}

func sortPortResults(results []common.PortServiceResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Host == results[j].Host {
			return results[i].Port < results[j].Port
		}
		return results[i].Host < results[j].Host
	})
}

func serviceIdentifyEnabled() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("FUSIONWEB_PORT_IDENTIFY")))
	return value != "0" && value != "false" && value != "off" && value != "no"
}

func cliProcessConcurrency(total int) int {
	if total <= 1 {
		return 1
	}
	if total > 5 {
		return 5
	}
	return total
}

func defaultInt(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
