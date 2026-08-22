package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SubdomainScanOptions struct {
	Domains            []string
	TimeoutSeconds     int
	MaxEnumerationTime int
	Threads            int
	RateLimit          int
	All                bool
	Recursive          bool
	Active             bool
	ResolveDNS         bool
	Sources            []string
	Logf               LogFunc
}

type SubdomainResult struct {
	Domain    string
	Subdomain string
	IPs       []string
	CNAME     string
	Source    string
	Raw       map[string]interface{}
}

type subfinderJSONResult struct {
	Host   string `json:"host"`
	Input  string `json:"input"`
	Source string `json:"source"`
}

func RunSubfinder(ctx context.Context, options SubdomainScanOptions) ([]SubdomainResult, error) {
	if _, err := ResolveTool("subfinder"); err != nil {
		return nil, err
	}
	domains := dedupeStrings(options.Domains)
	if len(domains) == 0 {
		return nil, nil
	}

	processes := cliProcessConcurrency(len(domains))
	jobs := make(chan string)
	resultsCh := make(chan []SubdomainResult, len(domains))
	errCh := make(chan error, len(domains))
	var wg sync.WaitGroup
	for i := 0; i < processes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				results, err := scanSubfinderDomain(ctx, domain, options)
				if err != nil {
					errCh <- err
					continue
				}
				resultsCh <- results
			}
		}()
	}

dispatch:
	for _, domain := range domains {
		select {
		case <-ctx.Done():
			break dispatch
		case jobs <- domain:
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

	seen := make(map[string]SubdomainResult)
	for batch := range resultsCh {
		for _, result := range batch {
			key := strings.ToLower(result.Subdomain)
			if key == "" {
				continue
			}
			if existing, ok := seen[key]; ok {
				existing.IPs = dedupeStrings(append(existing.IPs, result.IPs...))
				if existing.CNAME == "" {
					existing.CNAME = result.CNAME
				}
				seen[key] = existing
				continue
			}
			result.IPs = dedupeStrings(result.IPs)
			seen[key] = result
		}
	}
	out := make([]SubdomainResult, 0, len(seen))
	for _, result := range seen {
		out = append(out, result)
	}
	return out, nil
}

func scanSubfinderDomain(ctx context.Context, domain string, options SubdomainScanOptions) ([]SubdomainResult, error) {
	args := []string{
		"-d", domain,
		"-json",
		"-silent",
		"-disable-update-check",
	}
	if options.TimeoutSeconds > 0 {
		args = append(args, "-timeout", strconv.Itoa(options.TimeoutSeconds))
	}
	if options.MaxEnumerationTime > 0 {
		args = append(args, "-max-time", strconv.Itoa(options.MaxEnumerationTime))
	}
	if options.Threads > 0 {
		args = append(args, "-t", strconv.Itoa(options.Threads))
	}
	if options.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(options.RateLimit))
	}
	if len(options.Sources) > 0 {
		args = append(args, "-sources", strings.Join(options.Sources, ","))
	}
	if options.All {
		args = append(args, "-all")
	}
	if options.Recursive {
		args = append(args, "-recursive")
	}
	if options.Active {
		args = append(args, "-active")
	}

	timeout := time.Duration(defaultInt(options.MaxEnumerationTime, 10)+defaultInt(options.TimeoutSeconds, 30)+10) * time.Second
	result, err := Execute(ctx, "subfinder", args, ExecuteOptions{Timeout: timeout, Logf: options.Logf})
	if err != nil {
		return nil, err
	}
	return parseSubfinderOutput(ctx, domain, result.Stdout, options.ResolveDNS), nil
}

func parseSubfinderOutput(ctx context.Context, domain, stdout string, resolveDNS bool) []SubdomainResult {
	var results []SubdomainResult
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		item := subfinderJSONResult{}
		raw := map[string]interface{}{}
		if strings.HasPrefix(line, "{") {
			_ = json.Unmarshal([]byte(line), &item)
			_ = json.Unmarshal([]byte(line), &raw)
		} else {
			item.Host = line
		}
		host := strings.TrimSpace(item.Host)
		if host == "" {
			continue
		}
		if item.Input == "" {
			item.Input = domain
		}
		r := SubdomainResult{
			Domain:    item.Input,
			Subdomain: host,
			Source:    item.Source,
			Raw:       raw,
		}
		if resolveDNS {
			r.IPs, r.CNAME = resolveSubdomainDNS(ctx, host)
		}
		results = append(results, r)
	}
	return results
}

func resolveSubdomainDNS(ctx context.Context, host string) ([]string, string) {
	var cname string
	if c, err := net.DefaultResolver.LookupCNAME(ctx, host); err == nil {
		cname = strings.TrimSuffix(c, ".")
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, cname
	}
	return dedupeStrings(ips), cname
}

type DirectoryScanOptions struct {
	Targets        []string
	Paths          []string
	Threads        int
	TimeoutSeconds int
	Extensions     []string
	StatusCodes    []int
	FollowRedirect bool
	Rate           int
	Recursion      bool
	RecursionDepth int
	Logf           LogFunc
}

type DirectoryResult struct {
	Target           string
	URL              string
	Path             string
	StatusCode       int
	ContentLength    int64
	ContentType      string
	RedirectLocation string
	Source           string
	Raw              map[string]interface{}
}

type ffufOutput struct {
	Results []ffufResult `json:"results"`
}

type ffufResult struct {
	URL              string `json:"url"`
	StatusCode       int    `json:"status"`
	ContentLength    int64  `json:"length"`
	ContentType      string `json:"content-type"`
	RedirectLocation string `json:"redirectlocation"`
}

func RunFFUF(ctx context.Context, options DirectoryScanOptions) ([]DirectoryResult, error) {
	if _, err := ResolveTool("ffuf"); err != nil {
		return nil, err
	}
	targets := normalizeHTTPTargets(options.Targets)
	paths := normalizeWordlistPaths(options.Paths)
	if len(targets) == 0 || len(paths) == 0 {
		return nil, nil
	}

	wordlist, err := writeFFUFWordlist(paths)
	if err != nil {
		return nil, err
	}
	defer os.Remove(wordlist)

	processes := cliProcessConcurrency(len(targets))
	jobs := make(chan string)
	resultsCh := make(chan []DirectoryResult, len(targets))
	errCh := make(chan error, len(targets))
	var wg sync.WaitGroup
	for i := 0; i < processes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				results, err := scanFFUFTarget(ctx, target, wordlist, options)
				if err != nil {
					errCh <- err
					continue
				}
				resultsCh <- results
			}
		}()
	}

dispatch:
	for _, target := range targets {
		select {
		case <-ctx.Done():
			break dispatch
		case jobs <- target:
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

	seen := make(map[string]DirectoryResult)
	for batch := range resultsCh {
		for _, result := range batch {
			key := strings.ToLower(result.URL)
			if key == "" {
				continue
			}
			seen[key] = result
		}
	}
	out := make([]DirectoryResult, 0, len(seen))
	for _, result := range seen {
		out = append(out, result)
	}
	return out, nil
}

func scanFFUFTarget(ctx context.Context, target, wordlist string, options DirectoryScanOptions) ([]DirectoryResult, error) {
	output, err := os.CreateTemp("", "fusionweb-ffuf-*.json")
	if err != nil {
		return nil, err
	}
	outputPath := output.Name()
	_ = output.Close()
	defer os.Remove(outputPath)

	statusCodes := formatStatusCodes(options.StatusCodes)
	if statusCodes == "" {
		statusCodes = "200,204,301,302,307,401,403,405,500"
	}
	args := []string{
		"-u", strings.TrimRight(target, "/") + "/FUZZ",
		"-w", wordlist,
		"-of", "json",
		"-o", outputPath,
		"-t", strconv.Itoa(defaultInt(options.Threads, 50)),
		"-timeout", strconv.Itoa(defaultInt(options.TimeoutSeconds, 10)),
		"-mc", statusCodes,
	}
	if options.FollowRedirect {
		args = append(args, "-r")
	}
	if options.Rate > 0 {
		args = append(args, "-rate", strconv.Itoa(options.Rate))
	}
	if options.Recursion {
		args = append(args, "-recursion")
		if options.RecursionDepth > 0 {
			args = append(args, "-recursion-depth", strconv.Itoa(options.RecursionDepth))
		}
	}
	for _, ext := range options.Extensions {
		ext = strings.TrimSpace(strings.TrimPrefix(ext, "."))
		if ext != "" {
			args = append(args, "-e", ext)
		}
	}

	timeout := time.Duration(defaultInt(options.TimeoutSeconds, 10)+120) * time.Second
	result, err := Execute(ctx, "ffuf", args, ExecuteOptions{Timeout: timeout, Logf: options.Logf})
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 && strings.TrimSpace(result.Stdout) != "" {
		data = []byte(result.Stdout)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var parsed ffufOutput
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("解析 ffuf JSON 失败: %w", err)
	}
	return convertFFUFResults(target, parsed.Results), nil
}

func convertFFUFResults(target string, items []ffufResult) []DirectoryResult {
	results := make([]DirectoryResult, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.URL) == "" {
			continue
		}
		parsed, _ := url.Parse(item.URL)
		pathValue := ""
		if parsed != nil {
			pathValue = parsed.EscapedPath()
			if pathValue == "" {
				pathValue = parsed.Path
			}
		}
		raw := map[string]interface{}{
			"status":           item.StatusCode,
			"length":           item.ContentLength,
			"content_type":     item.ContentType,
			"redirectlocation": item.RedirectLocation,
		}
		results = append(results, DirectoryResult{
			Target:           target,
			URL:              item.URL,
			Path:             pathValue,
			StatusCode:       item.StatusCode,
			ContentLength:    item.ContentLength,
			ContentType:      item.ContentType,
			RedirectLocation: item.RedirectLocation,
			Source:           "ffuf",
			Raw:              raw,
		})
	}
	return results
}

func writeFFUFWordlist(paths []string) (string, error) {
	file, err := os.CreateTemp("", "fusionweb-ffuf-wordlist-*.txt")
	if err != nil {
		return "", err
	}
	defer file.Close()
	for _, item := range paths {
		item = strings.TrimSpace(strings.TrimPrefix(item, "/"))
		if item == "" {
			continue
		}
		if _, err := file.WriteString(item + "\n"); err != nil {
			_ = os.Remove(file.Name())
			return "", err
		}
	}
	return file.Name(), nil
}

func normalizeHTTPTargets(targets []string) []string {
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
		parsed.Path = strings.TrimRight(path.Clean("/"+strings.TrimSpace(parsed.Path)), "/")
		if parsed.Path == "." {
			parsed.Path = ""
		}
		parsed.RawQuery = ""
		parsed.Fragment = ""
		out = append(out, strings.TrimRight(parsed.String(), "/"))
	}
	return dedupeStrings(out)
}

func normalizeWordlistPaths(paths []string) []string {
	defaultPaths := []string{"admin", "login", "api", "actuator", "swagger-ui.html", "robots.txt", ".git/config"}
	if len(paths) == 0 {
		paths = defaultPaths
	}
	out := make([]string, 0, len(paths))
	for _, item := range paths {
		item = strings.TrimSpace(strings.TrimPrefix(item, "/"))
		if item != "" {
			out = append(out, item)
		}
	}
	return dedupeStrings(out)
}

func formatStatusCodes(codes []int) string {
	parts := make([]string, 0, len(codes))
	for _, code := range codes {
		if code >= 100 && code <= 599 {
			parts = append(parts, strconv.Itoa(code))
		}
	}
	return strings.Join(parts, ",")
}
