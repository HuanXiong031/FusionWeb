package service

import (
	coreUtils "FusionWeb/backend/core/utils"
	"FusionWeb/backend/database"
	"FusionWeb/backend/engine/cli"
	"FusionWeb/backend/engine/lib/bruteforce"
	"FusionWeb/backend/models"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type subdomainTaskOptions struct {
	Timeout            int      `json:"timeout"`
	MaxEnumerationTime int      `json:"maxEnumerationTime"`
	Threads            int      `json:"threads"`
	RateLimit          int      `json:"rateLimit"`
	All                bool     `json:"all"`
	Recursive          bool     `json:"recursive"`
	Active             bool     `json:"active"`
	ResolveDNS         bool     `json:"resolveDNS"`
	Sources            []string `json:"sources"`
}

type weakPasswordTaskOptions struct {
	Services    []string `json:"services"`
	Usernames   []string `json:"usernames"`
	Passwords   []string `json:"passwords"`
	Timeout     int      `json:"timeout"`
	Threads     int      `json:"threads"`
	StopOnFirst bool     `json:"stopOnFirst"`
	ForceScan   bool     `json:"forceScan"`
}

type directoryTaskOptions struct {
	Paths          []string `json:"paths"`
	Extensions     []string `json:"extensions"`
	StatusCodes    []int    `json:"statusCodes"`
	Threads        int      `json:"threads"`
	Timeout        int      `json:"timeout"`
	FollowRedirect bool     `json:"followRedirect"`
	Rate           int      `json:"rate"`
	Recursion      bool     `json:"recursion"`
	RecursionDepth int      `json:"recursionDepth"`
}

type jsTaskOptions struct {
	Threads           int      `json:"threads"`
	Timeout           int      `json:"timeout"`
	EnableSourcemap   bool     `json:"enableSourcemap"`
	EnableUnauthCheck bool     `json:"enableUnauthCheck"`
	MaxJSSize         int      `json:"maxJSSize"`
	MaxJSPerTarget    int      `json:"maxJSPerTarget"`
	SensitiveKeywords []string `json:"sensitiveKeywords"`
	RouteKeywords     []string `json:"routeKeywords"`
}

func (s *ScanService) RunSubdomainScan(targets []string, config *models.TaskConfig) (int, error) {
	var opts subdomainTaskOptions
	decodeTaskScanOptions(config, &opts)
	if opts.Timeout <= 0 {
		opts.Timeout = 30
	}
	if opts.MaxEnumerationTime <= 0 {
		opts.MaxEnumerationTime = 10
	}
	if opts.Threads <= 0 {
		opts.Threads = defaultPositive(config.ThreadCount, 10)
	}
	if !opts.ResolveDNS {
		opts.ResolveDNS = true
	}

	domains := collectSubdomainTargets(targets)
	if len(domains) == 0 {
		return 0, fmt.Errorf("没有可用的子域名扫描目标")
	}
	_, _ = database.DB.Exec("DELETE FROM subdomain_results WHERE task_id = $1", s.taskID)
	s.logInfo(fmt.Sprintf("开始子域名扫描，域名数: %d，工具: subfinder", len(domains)))
	results, err := cli.RunSubfinder(s.ctx, cli.SubdomainScanOptions{
		Domains:            domains,
		TimeoutSeconds:     opts.Timeout,
		MaxEnumerationTime: opts.MaxEnumerationTime,
		Threads:            opts.Threads,
		RateLimit:          opts.RateLimit,
		All:                opts.All,
		Recursive:          opts.Recursive,
		Active:             opts.Active,
		ResolveDNS:         opts.ResolveDNS,
		Sources:            opts.Sources,
		Logf:               s.taskCLILogger(),
	})
	if err != nil {
		return 0, err
	}
	if prefixes, loadErr := enabledScanDictionaryValues(ScanDictSubdomainPrefix); loadErr != nil {
		s.logWarning(fmt.Sprintf("加载子域名字典失败，跳过字典爆破: %v", loadErr))
	} else if len(prefixes) > 0 {
		dictResults := s.runSubdomainDictionaryLookup(domains, prefixes, opts.Threads, opts.Timeout)
		results = mergeSubdomainResults(results, dictResults)
		s.logInfo(fmt.Sprintf("子域名字典解析完成，前缀数: %d，命中 %d 条", len(prefixes), len(dictResults)))
	}
	for _, result := range results {
		if err := s.saveSubdomainResult(result); err != nil {
			s.logWarning(fmt.Sprintf("保存子域名结果失败: %v", err))
		}
	}
	s.logInfo(fmt.Sprintf("子域名扫描完成，发现 %d 条结果", len(results)))
	return len(results), nil
}

func (s *ScanService) RunDirectoryScan(targets []string, config *models.TaskConfig) (int, error) {
	var opts directoryTaskOptions
	decodeTaskScanOptions(config, &opts)
	if opts.Threads <= 0 {
		opts.Threads = defaultPositive(config.ThreadCount, 50)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultPositive(config.WebTimeout, 10)
	}
	if len(opts.Paths) == 0 {
		opts.Paths = parseJSONTextList(config.SelectedDicts)
	}
	if len(opts.Paths) == 0 {
		opts.Paths = s.scanDictionaryOrDefault(ScanDictDirectoryPath, []string{"admin", "login", "api", "actuator", "swagger-ui.html", "robots.txt", ".git/config"})
	}

	_, _ = database.DB.Exec("DELETE FROM directory_results WHERE task_id = $1", s.taskID)
	s.logInfo(fmt.Sprintf("开始目录扫描，目标数: %d，路径数: %d，工具: ffuf", len(targets), len(opts.Paths)))
	results, err := cli.RunFFUF(s.ctx, cli.DirectoryScanOptions{
		Targets:        targets,
		Paths:          opts.Paths,
		Threads:        opts.Threads,
		TimeoutSeconds: opts.Timeout,
		Extensions:     opts.Extensions,
		StatusCodes:    opts.StatusCodes,
		FollowRedirect: opts.FollowRedirect,
		Rate:           opts.Rate,
		Recursion:      opts.Recursion,
		RecursionDepth: opts.RecursionDepth,
		Logf:           s.taskCLILogger(),
	})
	if err != nil {
		return 0, err
	}
	for _, result := range results {
		if err := s.saveDirectoryResult(result); err != nil {
			s.logWarning(fmt.Sprintf("保存目录扫描结果失败: %v", err))
		}
	}
	s.logInfo(fmt.Sprintf("目录扫描完成，发现 %d 条结果", len(results)))
	return len(results), nil
}

func (s *ScanService) RunWeakPasswordScan(targets []string, config *models.TaskConfig) (int, error) {
	var opts weakPasswordTaskOptions
	decodeTaskScanOptions(config, &opts)
	if opts.Timeout <= 0 {
		opts.Timeout = 5
	}
	if opts.Threads <= 0 {
		opts.Threads = defaultPositive(config.ThreadCount, 10)
	}
	if len(opts.Usernames) == 0 {
		opts.Usernames = s.scanDictionaryOrDefault(ScanDictWeakUsername, []string{"root", "admin", "user", "test", "postgres", "mysql"})
	}
	if len(opts.Passwords) == 0 {
		opts.Passwords = s.scanDictionaryOrDefault(ScanDictWeakPassword, []string{"", "123456", "password", "admin", "root", "12345678"})
	}

	jobs := collectWeakPasswordTargets(targets, opts.Services)
	if len(jobs) == 0 {
		return 0, fmt.Errorf("没有可用的弱口令扫描目标，请输入 host:port 或 service://host:port")
	}

	_, _ = database.DB.Exec("DELETE FROM weak_password_results WHERE task_id = $1", s.taskID)
	s.logInfo(fmt.Sprintf("开始弱口令扫描，目标服务数: %d", len(jobs)))

	workers := opts.Threads
	if workers <= 0 {
		workers = 10
	}
	if workers > 100 {
		workers = 100
	}
	sem := make(chan struct{}, workers)
	resultsCh := make(chan weakPasswordTarget, len(jobs))
	var wg sync.WaitGroup
	for _, job := range jobs {
		if doneClosed(s.ctxDone()) {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(job weakPasswordTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			if !opts.ForceScan && !tcpPortOpen(job.Host, job.Port, time.Duration(opts.Timeout)*time.Second) {
				return
			}
			resultCh := bruteforce.Crack(s.ctx, bruteforce.Options{
				Host:     job.Host,
				Port:     job.Port,
				Service:  bruteforce.ServiceType(job.Service),
				UserDict: opts.Usernames,
				PassDict: opts.Passwords,
				Timeout:  time.Duration(opts.Timeout) * time.Second,
			})
			for result := range resultCh {
				if result.Success {
					job.Username = result.Username
					job.Password = result.Password
					resultsCh <- job
					if opts.StopOnFirst {
						return
					}
				}
			}
		}(job)
	}
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	count := 0
	for result := range resultsCh {
		if err := s.saveWeakPasswordResult(result); err != nil {
			s.logWarning(fmt.Sprintf("保存弱口令结果失败: %v", err))
			continue
		}
		count++
	}
	s.logInfo(fmt.Sprintf("弱口令扫描完成，发现 %d 条结果", count))
	return count, nil
}

func (s *ScanService) RunJSScan(targets []string, config *models.TaskConfig) (int, error) {
	var opts jsTaskOptions
	decodeTaskScanOptions(config, &opts)
	if opts.Timeout <= 0 {
		opts.Timeout = defaultPositive(config.WebTimeout, 10)
	}
	if opts.Threads <= 0 {
		opts.Threads = defaultPositive(config.ThreadCount, 10)
	}
	if opts.MaxJSSize <= 0 {
		opts.MaxJSSize = 5 * 1024 * 1024
	}
	if opts.MaxJSPerTarget <= 0 {
		opts.MaxJSPerTarget = 200
	}
	if len(opts.SensitiveKeywords) == 0 {
		opts.SensitiveKeywords = s.scanDictionaryOrDefault(ScanDictJSSensitive, []string{"password", "passwd", "secret", "token", "access_token", "api_key", "private_key", "client_secret"})
	}
	if len(opts.RouteKeywords) == 0 {
		opts.RouteKeywords = s.scanDictionaryOrDefault(ScanDictJSRoute, []string{"/api/", "/admin", "/swagger", "/actuator"})
	}

	httpTargets := normalizeServiceHTTPTargets(targets)
	if len(httpTargets) == 0 {
		return 0, fmt.Errorf("没有可用的 JS 扫描目标")
	}

	_, _ = database.DB.Exec("DELETE FROM js_scan_results WHERE task_id = $1", s.taskID)
	s.logInfo(fmt.Sprintf("开始 JS 扫描，目标数: %d", len(httpTargets)))
	client := jsHTTPClient(time.Duration(opts.Timeout) * time.Second)
	defer client.CloseIdleConnections()

	workers := opts.Threads
	if workers > 5 {
		workers = 5
	}
	if workers > len(httpTargets) {
		workers = len(httpTargets)
	}
	sem := make(chan struct{}, workers)
	resultsCh := make(chan jsScanFinding, len(httpTargets)*16)
	var wg sync.WaitGroup
	for _, target := range httpTargets {
		sem <- struct{}{}
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, finding := range scanJSForTarget(s.ctxDone(), client, target, opts) {
				resultsCh <- finding
			}
		}(target)
	}
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	count := 0
	for finding := range resultsCh {
		if err := s.saveJSScanResult(finding); err != nil {
			s.logWarning(fmt.Sprintf("保存 JS 扫描结果失败: %v", err))
			continue
		}
		count++
	}
	s.logInfo(fmt.Sprintf("JS 扫描完成，发现 %d 条结果", count))
	return count, nil
}

func (s *ScanService) ctxDone() <-chan struct{} {
	if s.ctx == nil {
		return nil
	}
	return s.ctx.Done()
}

func (s *ScanService) taskCLILogger() cli.LogFunc {
	return func(level, format string, args ...interface{}) {
		message := fmt.Sprintf(format, args...)
		switch strings.ToUpper(level) {
		case "ERROR":
			s.logError(message)
		case "WARN":
			s.logWarning(message)
		case "DEBUG":
			return
		default:
			s.logInfo(message)
		}
	}
}

func (s *ScanService) scanDictionaryOrDefault(dictType string, fallback []string) []string {
	values, err := enabledScanDictionaryValues(dictType)
	if err != nil {
		s.logWarning(fmt.Sprintf("加载扫描字典失败[%s]: %v，将使用默认字典", dictType, err))
		return fallback
	}
	if len(values) == 0 {
		return fallback
	}
	return values
}

func decodeTaskScanOptions(config *models.TaskConfig, out interface{}) {
	if config == nil || strings.TrimSpace(config.ScanOptions) == "" {
		return
	}
	_ = json.Unmarshal([]byte(config.ScanOptions), out)
}

func collectSubdomainTargets(targets []string) []string {
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if strings.Contains(target, "://") {
			if parsed, err := url.Parse(target); err == nil {
				target = parsed.Hostname()
			}
		}
		target = strings.Trim(target, ".")
		if target == "" || net.ParseIP(target) != nil || strings.Contains(target, ":") {
			continue
		}
		out = append(out, target)
	}
	return coreUtils.RemoveDuplicateElement(out)
}

func (s *ScanService) runSubdomainDictionaryLookup(domains, prefixes []string, threads, timeout int) []cli.SubdomainResult {
	if len(domains) == 0 || len(prefixes) == 0 {
		return nil
	}
	if threads <= 0 {
		threads = 10
	}
	if threads > 100 {
		threads = 100
	}
	if timeout <= 0 {
		timeout = 5
	}
	type job struct {
		domain string
		name   string
	}
	jobs := make(chan job)
	resultsCh := make(chan cli.SubdomainResult, len(domains))
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if doneClosed(s.ctxDone()) {
					return
				}
				fqdn := strings.Trim(item.name, ".") + "." + strings.Trim(item.domain, ".")
				ctx := s.ctx
				if ctx == nil {
					ctx = context.Background()
				}
				lookupCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
				ips, err := net.DefaultResolver.LookupHost(lookupCtx, fqdn)
				cancel()
				if err != nil || len(ips) == 0 {
					continue
				}
				resultsCh <- cli.SubdomainResult{
					Domain:    item.domain,
					Subdomain: fqdn,
					IPs:       ips,
					Source:    "dictionary",
					Raw: map[string]interface{}{
						"prefix": item.name,
					},
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, domain := range domains {
			for _, prefix := range prefixes {
				prefix = strings.TrimSpace(prefix)
				if prefix == "" || strings.Contains(prefix, ".") {
					continue
				}
				select {
				case <-s.ctxDone():
					return
				case jobs <- job{domain: domain, name: prefix}:
				}
			}
		}
	}()
	results := make([]cli.SubdomainResult, 0)
	go func() {
		wg.Wait()
		close(resultsCh)
	}()
	for result := range resultsCh {
		results = append(results, result)
	}
	return results
}

func mergeSubdomainResults(primary, secondary []cli.SubdomainResult) []cli.SubdomainResult {
	seen := make(map[string]struct{}, len(primary)+len(secondary))
	out := make([]cli.SubdomainResult, 0, len(primary)+len(secondary))
	for _, item := range append(primary, secondary...) {
		key := strings.ToLower(strings.TrimSpace(item.Subdomain))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func parseJSONTextList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var list []string
	if strings.HasPrefix(raw, "[") {
		_ = json.Unmarshal([]byte(raw), &list)
	} else {
		list = strings.FieldsFunc(raw, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ','
		})
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return coreUtils.RemoveDuplicateElement(out)
}

func (s *ScanService) saveSubdomainResult(result cli.SubdomainResult) error {
	ipsJSON, _ := json.Marshal(result.IPs)
	extraJSON, _ := json.Marshal(result.Raw)
	return retryReconWrite(func(timeStr string) error {
		_, err := database.DB.Exec(`
			INSERT INTO subdomain_results (task_id, scan_scope, user_id, domain, subdomain, ip_addresses, cname, source, extra_data, discovered_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`, s.taskID, s.taskType, s.userID, result.Domain, result.Subdomain, string(ipsJSON), result.CNAME, result.Source, string(extraJSON), timeStr)
		return err
	})
}

func (s *ScanService) saveDirectoryResult(result cli.DirectoryResult) error {
	extraJSON, _ := json.Marshal(result.Raw)
	return retryReconWrite(func(timeStr string) error {
		_, err := database.DB.Exec(`
			INSERT INTO directory_results (task_id, scan_scope, user_id, target, url, path, status_code, content_length, content_type, redirect_location, source, extra_data, discovered_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		`, s.taskID, s.taskType, s.userID, result.Target, result.URL, result.Path, result.StatusCode, result.ContentLength, result.ContentType, result.RedirectLocation, result.Source, string(extraJSON), timeStr)
		return err
	})
}

type weakPasswordTarget struct {
	Target   string
	Host     string
	Port     int
	Service  string
	Username string
	Password string
}

func (s *ScanService) saveWeakPasswordResult(result weakPasswordTarget) error {
	extraJSON, _ := json.Marshal(map[string]interface{}{
		"target": result.Target,
	})
	return retryReconWrite(func(timeStr string) error {
		_, err := database.DB.Exec(`
			INSERT INTO weak_password_results (task_id, scan_scope, user_id, target, host, port, service, username, password, severity, extra_data, discovered_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'high', $10, $11)
		`, s.taskID, s.taskType, s.userID, result.Target, result.Host, result.Port, result.Service, result.Username, result.Password, string(extraJSON), timeStr)
		return err
	})
}

func collectWeakPasswordTargets(targets, services []string) []weakPasswordTarget {
	var out []weakPasswordTarget
	for _, raw := range targets {
		target := strings.TrimSpace(raw)
		if target == "" {
			continue
		}
		serviceFromTarget := ""
		if strings.Contains(target, "://") {
			if parsed, err := url.Parse(target); err == nil {
				serviceFromTarget = normalizeWeakService(parsed.Scheme)
				host := parsed.Hostname()
				port := portFromURL(parsed)
				if host != "" && port > 0 && serviceFromTarget != "" {
					out = append(out, weakPasswordTarget{Target: target, Host: host, Port: port, Service: serviceFromTarget})
					continue
				}
			}
		}
		host, port, ok := splitHostPortForWeak(target)
		if !ok {
			continue
		}
		candidateServices := services
		if len(candidateServices) == 0 {
			candidateServices = []string{guessWeakService(port)}
		}
		for _, service := range candidateServices {
			service = normalizeWeakService(service)
			if service == "" {
				continue
			}
			out = append(out, weakPasswordTarget{Target: target, Host: host, Port: port, Service: service})
		}
	}
	return out
}

func splitHostPortForWeak(target string) (string, int, bool) {
	if host, portText, err := net.SplitHostPort(target); err == nil {
		port, err := strconv.Atoi(portText)
		return strings.Trim(host, "[]"), port, err == nil && port > 0
	}
	idx := strings.LastIndex(target, ":")
	if idx <= 0 || idx >= len(target)-1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(strings.TrimSpace(target[idx+1:]))
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, false
	}
	host := strings.Trim(strings.TrimSpace(target[:idx]), "[]")
	return host, port, host != ""
}

func portFromURL(parsed *url.URL) int {
	if parsed.Port() != "" {
		port, _ := strconv.Atoi(parsed.Port())
		return port
	}
	switch strings.ToLower(parsed.Scheme) {
	case "ssh":
		return 22
	case "ftp":
		return 21
	case "mysql":
		return 3306
	case "redis":
		return 6379
	case "postgres", "postgresql":
		return 5432
	}
	return 0
}

func normalizeWeakService(service string) string {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "ssh", "ftp", "mysql", "redis":
		return strings.ToLower(strings.TrimSpace(service))
	case "postgres", "postgresql":
		return "postgresql"
	default:
		return ""
	}
}

func guessWeakService(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	default:
		return ""
	}
}

func tcpPortOpen(host string, port int, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

type jsScanFinding struct {
	Target     string
	ResultType string
	Value      string
	SourceURL  string
	Severity   string
	Extra      map[string]interface{}
}

var (
	jsScriptSrcPattern = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"'<>]+)["']`)
	jsPathPattern      = regexp.MustCompile(`["'` + "`" + `](\/[a-zA-Z0-9_\-/.?=&%~+#@:]{1,256})["'` + "`" + `]`)
	jsAbsURLPattern    = regexp.MustCompile(`https?://[a-zA-Z0-9._\-]+(?::\d+)?(?:/[a-zA-Z0-9_\-/.?=&%~+#@:]*)?`)
	jsIPPattern        = regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b`)
	jsEmailPattern     = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	jsJWTPattern       = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`)
	jsSecretPattern    = regexp.MustCompile(`(?i)(access[_\-]?key|api[_\-]?key|secret[_\-]?key|secret[_\-]?token|app[_\-]?key|app[_\-]?secret|auth[_\-]?token|access[_\-]?token|client[_\-]?secret|private[_\-]?key|aws[_\-]?secret)["'\s:=]+["']?([A-Za-z0-9_\-]{16,256})["']?`)
)

func scanJSForTarget(done <-chan struct{}, client *http.Client, target string, opts jsTaskOptions) []jsScanFinding {
	if doneClosed(done) {
		return nil
	}
	body, err := jsHTTPGet(client, target, opts.MaxJSSize)
	if err != nil {
		return nil
	}
	findings := analyzeJSContent(target, target, string(body), opts)
	jsURLs := extractJSURLs(string(body), target)
	if len(jsURLs) > opts.MaxJSPerTarget {
		jsURLs = jsURLs[:opts.MaxJSPerTarget]
	}
	for _, jsURL := range jsURLs {
		findings = append(findings, jsScanFinding{Target: target, ResultType: "js_link", Value: jsURL, SourceURL: target, Severity: "info"})
		if doneClosed(done) {
			break
		}
		jsBody, err := jsHTTPGet(client, jsURL, opts.MaxJSSize)
		if err != nil {
			continue
		}
		findings = append(findings, analyzeJSContent(target, jsURL, string(jsBody), opts)...)
	}
	return dedupeJSFindings(findings)
}

func doneClosed(done <-chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func extractJSURLs(html, base string) []string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, match := range jsScriptSrcPattern.FindAllStringSubmatch(html, -1) {
		if len(match) < 2 {
			continue
		}
		ref, err := url.Parse(strings.TrimSpace(match[1]))
		if err != nil {
			continue
		}
		abs := baseURL.ResolveReference(ref).String()
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}
		out = append(out, abs)
	}
	return out
}

func analyzeJSContent(target, sourceURL, content string, opts jsTaskOptions) []jsScanFinding {
	var out []jsScanFinding
	appendFinding := func(resultType, value, severity string, extra map[string]interface{}) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		out = append(out, jsScanFinding{Target: target, ResultType: resultType, Value: value, SourceURL: sourceURL, Severity: severity, Extra: extra})
	}
	for _, match := range jsPathPattern.FindAllStringSubmatch(content, -1) {
		if len(match) >= 2 {
			severity := "info"
			if matchesAnyKeyword(match[1], opts.RouteKeywords) {
				severity = "high"
			}
			appendFinding("api_path", match[1], severity, nil)
		}
	}
	for _, value := range jsAbsURLPattern.FindAllString(content, -1) {
		appendFinding("url", value, "info", nil)
	}
	for _, value := range jsIPPattern.FindAllString(content, -1) {
		appendFinding("ip", value, "low", nil)
	}
	for _, value := range jsEmailPattern.FindAllString(content, -1) {
		appendFinding("email", value, "low", nil)
	}
	for _, value := range jsJWTPattern.FindAllString(content, -1) {
		appendFinding("jwt", value, "high", nil)
	}
	for _, match := range jsSecretPattern.FindAllStringSubmatch(content, -1) {
		if len(match) >= 3 {
			appendFinding("secret", match[1]+"="+match[2], "critical", map[string]interface{}{"key": match[1]})
		}
	}
	for _, keyword := range opts.SensitiveKeywords {
		keyword = strings.TrimSpace(keyword)
		if keyword == "" || !strings.Contains(strings.ToLower(content), strings.ToLower(keyword)) {
			continue
		}
		appendFinding("keyword", keyword, "medium", map[string]interface{}{"keyword": keyword})
	}
	return out
}

func matchesAnyKeyword(value string, keywords []string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	for _, keyword := range keywords {
		keyword = strings.ToLower(strings.TrimSpace(keyword))
		if keyword != "" && strings.Contains(value, keyword) {
			return true
		}
	}
	return false
}

func dedupeJSFindings(items []jsScanFinding) []jsScanFinding {
	seen := make(map[string]struct{}, len(items))
	out := make([]jsScanFinding, 0, len(items))
	for _, item := range items {
		key := item.Target + "\x00" + item.ResultType + "\x00" + item.Value + "\x00" + item.SourceURL
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func (s *ScanService) saveJSScanResult(result jsScanFinding) error {
	extraJSON, _ := json.Marshal(result.Extra)
	if result.Severity == "" {
		result.Severity = "info"
	}
	return retryReconWrite(func(timeStr string) error {
		_, err := database.DB.Exec(`
			INSERT INTO js_scan_results (task_id, scan_scope, user_id, target, result_type, value, source_url, severity, extra_data, discovered_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`, s.taskID, s.taskType, s.userID, result.Target, result.ResultType, result.Value, result.SourceURL, result.Severity, string(extraJSON), timeStr)
		return err
	})
}

func jsHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func jsHTTPGet(client *http.Client, target string, maxSize int) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 FusionWeb JSScanner")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if maxSize <= 0 {
		maxSize = 5 * 1024 * 1024
	}
	return io.ReadAll(io.LimitReader(resp.Body, int64(maxSize)))
}

func normalizeServiceHTTPTargets(targets []string) []string {
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if !strings.Contains(target, "://") {
			target = "http://" + target
		}
		parsed, err := url.Parse(target)
		if err != nil || parsed.Host == "" {
			continue
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			continue
		}
		parsed.Fragment = ""
		out = append(out, strings.TrimRight(parsed.String(), "/"))
	}
	return coreUtils.RemoveDuplicateElement(out)
}

func defaultPositive(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}
