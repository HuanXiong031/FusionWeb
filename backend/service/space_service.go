package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/utils"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	SpaceProviderFOFA    = "fofa"
	SpaceProviderHunter  = "hunter"
	SpaceProviderQuake   = "quake"
	SpaceProviderShodan  = "shodan"
	SpaceProviderZoomEye = "zoomeye"
)

var fofaRestrictedProductFieldPattern = regexp.MustCompile(`(?i)(^|[\s(&|])product\s*(!?={1,2}|:)\s*`)

type SpaceEngineKey struct {
	ID              int64  `json:"id"`
	Provider        string `json:"provider"`
	Name            string `json:"name"`
	APIKey          string `json:"apiKey,omitempty"`
	MaskedAPIKey    string `json:"maskedApiKey,omitempty"`
	SecretKey       string `json:"secretKey,omitempty"`
	MaskedSecretKey string `json:"maskedSecretKey,omitempty"`
	Version         string `json:"version,omitempty"`
	Enabled         bool   `json:"enabled"`
	Description     string `json:"description,omitempty"`
	LastTestStatus  string `json:"lastTestStatus,omitempty"`
	LastTestMessage string `json:"lastTestMessage,omitempty"`
	LastTestAt      string `json:"lastTestAt,omitempty"`
	CreatedBy       int    `json:"createdBy,omitempty"`
	CreatedAt       string `json:"createdAt,omitempty"`
	UpdatedAt       string `json:"updatedAt,omitempty"`
}

type SpaceSearchRequest struct {
	Provider string `json:"provider"`
	Query    string `json:"query"`
	Page     int    `json:"page"`
	PageSize int    `json:"pageSize"`
}

type SpaceSearchResult struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Domain   string `json:"domain"`
	Title    string `json:"title"`
	Server   string `json:"server"`
	Country  string `json:"country"`
	City     string `json:"city"`
	Banner   string `json:"banner"`
	ICP      string `json:"icp"`
	Product  string `json:"product"`
	OS       string `json:"os"`
}

type SpaceSearchResponse struct {
	Provider string              `json:"provider"`
	Query    string              `json:"query"`
	Page     int                 `json:"page"`
	PageSize int                 `json:"pageSize"`
	Total    int                 `json:"total"`
	List     []SpaceSearchResult `json:"list"`
}

type SpaceEngineTestResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type SpaceService struct {
	client *http.Client
}

func NewSpaceService() *SpaceService {
	return &SpaceService{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *SpaceService) ListEngineKeys(userID int) ([]SpaceEngineKey, error) {
	if database.DB == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	query := `SELECT id, provider, name, api_key, secret_key, version, enabled, description,
		last_test_status, last_test_message, CAST(last_test_at AS TEXT), created_by, CAST(created_at AS TEXT), CAST(updated_at AS TEXT)
		FROM space_engine_keys WHERE 1=1`
	args := make([]interface{}, 0)
	query += " ORDER BY provider ASC, enabled DESC, id DESC"

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]SpaceEngineKey, 0)
	for rows.Next() {
		item, err := scanSpaceEngineKey(rows, false)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SpaceService) SaveEngineKey(item SpaceEngineKey, userID int) (SpaceEngineKey, error) {
	if database.DB == nil {
		return SpaceEngineKey{}, fmt.Errorf("数据库未初始化")
	}
	item.Provider = normalizeSpaceProvider(item.Provider)
	item.Name = strings.TrimSpace(item.Name)
	item.APIKey = strings.TrimSpace(item.APIKey)
	item.SecretKey = strings.TrimSpace(item.SecretKey)
	item.Version = normalizeSpaceVersion(item.Provider, item.Version)
	item.Description = strings.TrimSpace(item.Description)
	item.APIKey, item.SecretKey = normalizeFofaCredentials(item.Provider, item.APIKey, item.SecretKey)
	if item.Provider == "" {
		return SpaceEngineKey{}, fmt.Errorf("空间引擎不支持")
	}
	if item.Name == "" {
		item.Name = getSpaceProviderLabel(item.Provider)
	}
	if item.ID <= 0 && item.APIKey == "" {
		return SpaceEngineKey{}, fmt.Errorf("请输入 API Key")
	}
	now := utils.GetCurrentTimeString()
	enabled := boolToInt(item.Enabled)
	if item.ID > 0 {
		existing, err := s.GetEngineKey(item.ID, userID, true)
		if err != nil {
			if err == sql.ErrNoRows {
				return SpaceEngineKey{}, fmt.Errorf("空间引擎配置不存在")
			}
			return SpaceEngineKey{}, err
		}
		if item.APIKey == "" {
			item.APIKey = existing.APIKey
		}
		if item.SecretKey == "" {
			item.SecretKey = existing.SecretKey
		}
		item.APIKey, item.SecretKey = normalizeFofaCredentials(item.Provider, item.APIKey, item.SecretKey)
		if item.APIKey == "" {
			return SpaceEngineKey{}, fmt.Errorf("请输入 API Key")
		}
		args := []interface{}{item.Provider, item.Name, item.APIKey, item.SecretKey, item.Version, enabled, item.Description, now, item.ID}
		result, err := database.DB.Exec(`UPDATE space_engine_keys
			SET provider = ?, name = ?, api_key = ?, secret_key = ?, version = ?, enabled = ?, description = ?, updated_at = ?
			WHERE id = ?`, args...)
		if err != nil {
			return SpaceEngineKey{}, err
		}
		if rows, _ := result.RowsAffected(); rows == 0 {
			return SpaceEngineKey{}, fmt.Errorf("空间引擎配置不存在")
		}
		return s.GetEngineKey(item.ID, userID, false)
	}

	id, err := database.InsertAndReturnID(`INSERT INTO space_engine_keys
		(provider, name, api_key, secret_key, version, enabled, description, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.Provider, item.Name, item.APIKey, item.SecretKey, item.Version, enabled, item.Description, userID, now, now)
	if err != nil {
		return SpaceEngineKey{}, err
	}
	return s.GetEngineKey(id, userID, false)
}

func (s *SpaceService) DeleteEngineKey(id int64, userID int) error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}
	query := "DELETE FROM space_engine_keys WHERE id = ?"
	args := []interface{}{id}
	result, err := database.DB.Exec(query, args...)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("空间引擎配置不存在")
	}
	return nil
}

func (s *SpaceService) GetEngineKey(id int64, userID int, includeSecret bool) (SpaceEngineKey, error) {
	if database.DB == nil {
		return SpaceEngineKey{}, fmt.Errorf("数据库未初始化")
	}
	query := `SELECT id, provider, name, api_key, secret_key, version, enabled, description,
		last_test_status, last_test_message, CAST(last_test_at AS TEXT), created_by, CAST(created_at AS TEXT), CAST(updated_at AS TEXT)
		FROM space_engine_keys WHERE id = ?`
	args := []interface{}{id}
	return scanSpaceEngineKey(database.DB.QueryRow(query, args...), includeSecret)
}

func (s *SpaceService) TestEngineKey(id int64, userID int) (SpaceEngineTestResult, error) {
	item, err := s.GetEngineKey(id, userID, true)
	if err != nil {
		return SpaceEngineTestResult{}, err
	}
	req := SpaceSearchRequest{
		Provider: item.Provider,
		Query:    defaultSpaceTestQuery(item.Provider),
		Page:     1,
		PageSize: 1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = s.searchWithKey(ctx, req, item)
	status := "success"
	message := "连接成功"
	success := true
	if err != nil {
		status = "failed"
		message = err.Error()
		success = false
	}
	_ = s.updateTestState(id, userID, status, message)
	return SpaceEngineTestResult{Success: success, Message: message}, nil
}

func (s *SpaceService) Search(ctx context.Context, req SpaceSearchRequest, userID int) (SpaceSearchResponse, error) {
	req.Provider = normalizeSpaceProvider(req.Provider)
	req.Query = strings.TrimSpace(req.Query)
	req.Page, req.PageSize = normalizeSpacePagination(req.Provider, req.Page, req.PageSize)
	if req.Provider == "" {
		return SpaceSearchResponse{}, fmt.Errorf("空间引擎不支持")
	}
	if req.Query == "" {
		return SpaceSearchResponse{}, fmt.Errorf("请输入查询语句")
	}
	if err := validateSpaceSearchQuery(req.Provider, req.Query); err != nil {
		return SpaceSearchResponse{}, err
	}
	key, err := s.findActiveEngineKey(req.Provider, userID)
	if err != nil {
		return SpaceSearchResponse{}, err
	}
	response, err := s.searchWithKey(ctx, req, key)
	if err != nil {
		return SpaceSearchResponse{}, err
	}
	_ = s.saveSearchResults(req, response.List, userID)
	return response, nil
}

func (s *SpaceService) searchWithKey(ctx context.Context, req SpaceSearchRequest, key SpaceEngineKey) (SpaceSearchResponse, error) {
	switch req.Provider {
	case SpaceProviderFOFA:
		return s.searchFOFA(ctx, req, key)
	case SpaceProviderHunter:
		return s.searchHunter(ctx, req, key)
	case SpaceProviderQuake:
		return s.searchQuake(ctx, req, key)
	case SpaceProviderShodan:
		return s.searchShodan(ctx, req, key)
	case SpaceProviderZoomEye:
		return s.searchZoomEye(ctx, req, key)
	default:
		return SpaceSearchResponse{}, fmt.Errorf("空间引擎不支持")
	}
}

func (s *SpaceService) findActiveEngineKey(provider string, userID int) (SpaceEngineKey, error) {
	query := `SELECT id, provider, name, api_key, secret_key, version, enabled, description,
		last_test_status, last_test_message, CAST(last_test_at AS TEXT), created_by, CAST(created_at AS TEXT), CAST(updated_at AS TEXT)
		FROM space_engine_keys
		WHERE provider = ? AND enabled = 1`
	args := []interface{}{provider}
	query += " ORDER BY id DESC LIMIT 1"
	item, err := scanSpaceEngineKey(database.DB.QueryRow(query, args...), true)
	if err == sql.ErrNoRows {
		return SpaceEngineKey{}, fmt.Errorf("未配置或未启用 %s API Key", getSpaceProviderLabel(provider))
	}
	if err != nil {
		return SpaceEngineKey{}, err
	}
	if item.APIKey == "" {
		return SpaceEngineKey{}, fmt.Errorf("%s API Key 为空", getSpaceProviderLabel(provider))
	}
	return item, nil
}

func (s *SpaceService) updateTestState(id int64, userID int, status, message string) error {
	query := `UPDATE space_engine_keys SET last_test_status = ?, last_test_message = ?, last_test_at = ?, updated_at = ? WHERE id = ?`
	now := utils.GetCurrentTimeString()
	args := []interface{}{status, truncateSpaceText(message, 1000), now, now, id}
	_, err := database.DB.Exec(query, args...)
	return err
}

func (s *SpaceService) saveSearchResults(req SpaceSearchRequest, rows []SpaceSearchResult, userID int) error {
	if len(rows) == 0 || database.DB == nil {
		return nil
	}
	now := utils.GetCurrentTimeString()
	for _, row := range rows {
		raw, _ := json.Marshal(row)
		_, err := database.DB.Exec(`INSERT INTO space_search_results
			(provider, query, user_id, host, ip, port, protocol, domain, title, server, country, city, banner, icp, product, os, raw_data, searched_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			req.Provider, req.Query, userID, row.Host, row.IP, row.Port, row.Protocol, row.Domain, row.Title, row.Server,
			row.Country, row.City, truncateSpaceText(row.Banner, 4096), row.ICP, row.Product, row.OS, string(raw), now)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SpaceService) searchFOFA(ctx context.Context, req SpaceSearchRequest, key SpaceEngineKey) (SpaceSearchResponse, error) {
	version := normalizeSpaceVersion(SpaceProviderFOFA, key.Version)
	baseURL := "https://fofa.info"
	if version == "v5" {
		baseURL = "https://v5.fofa.info"
	}
	apiKey, email := normalizeFofaCredentials(SpaceProviderFOFA, key.APIKey, key.SecretKey)
	if apiKey == "" {
		return SpaceSearchResponse{}, fmt.Errorf("FOFA API Key 为空")
	}
	queryBase64 := base64.StdEncoding.EncodeToString([]byte(req.Query))
	params := url.Values{}
	params.Set("key", apiKey)
	if email != "" {
		params.Set("email", email)
	}
	params.Set("qbase64", queryBase64)
	params.Set("page", strconv.Itoa(req.Page))
	params.Set("size", strconv.Itoa(req.PageSize))
	params.Set("fields", "host,ip,port,protocol,domain,title,server,country,city,icp,os")
	apiURL := fmt.Sprintf("%s/api/v1/search/all?%s", baseURL, params.Encode())
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return SpaceSearchResponse{}, err
	}
	body, err := s.doRequest(httpReq)
	if err != nil {
		return SpaceSearchResponse{}, err
	}
	var result struct {
		Error   bool       `json:"error"`
		ErrMsg  string     `json:"errmsg"`
		Page    int        `json:"page"`
		Size    int        `json:"size"`
		Results [][]string `json:"results"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return SpaceSearchResponse{}, fmt.Errorf("FOFA 响应解析失败: %w", err)
	}
	if result.Error {
		return SpaceSearchResponse{}, fmt.Errorf("FOFA 查询失败: %s", result.ErrMsg)
	}
	rows := make([]SpaceSearchResult, 0, len(result.Results))
	for _, item := range result.Results {
		if len(item) < 11 {
			continue
		}
		port, _ := strconv.Atoi(item[2])
		rows = append(rows, SpaceSearchResult{
			Host: item[0], IP: item[1], Port: port, Protocol: item[3], Domain: item[4],
			Title: item[5], Server: item[6], Country: item[7], City: item[8],
			ICP: item[9], OS: item[10],
		})
	}
	total := result.Size
	if total == 0 {
		total = len(rows)
	}
	return SpaceSearchResponse{Provider: req.Provider, Query: req.Query, Page: req.Page, PageSize: req.PageSize, Total: total, List: rows}, nil
}

func (s *SpaceService) searchHunter(ctx context.Context, req SpaceSearchRequest, key SpaceEngineKey) (SpaceSearchResponse, error) {
	queryBase64 := base64.URLEncoding.EncodeToString([]byte(req.Query))
	apiURL := fmt.Sprintf(
		"https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%d&page_size=%d&is_web=3",
		url.QueryEscape(key.APIKey),
		url.QueryEscape(queryBase64),
		req.Page,
		req.PageSize,
	)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return SpaceSearchResponse{}, err
	}
	body, err := s.doRequest(httpReq)
	if err != nil {
		return SpaceSearchResponse{}, err
	}
	var result struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Total int `json:"total"`
			Arr   []struct {
				URL       string `json:"url"`
				IP        string `json:"ip"`
				Port      int    `json:"port"`
				WebTitle  string `json:"web_title"`
				Domain    string `json:"domain"`
				Protocol  string `json:"protocol"`
				OS        string `json:"os"`
				Number    string `json:"number"`
				Country   string `json:"country"`
				City      string `json:"city"`
				Banner    string `json:"banner"`
				Component []struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"component"`
			} `json:"arr"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return SpaceSearchResponse{}, fmt.Errorf("Hunter 响应解析失败: %w", err)
	}
	if result.Code != 200 {
		return SpaceSearchResponse{}, fmt.Errorf("Hunter 查询失败: %s", result.Message)
	}
	rows := make([]SpaceSearchResult, 0, len(result.Data.Arr))
	for _, item := range result.Data.Arr {
		components := make([]string, 0, len(item.Component))
		for _, component := range item.Component {
			if component.Name != "" {
				if component.Version != "" {
					components = append(components, component.Name+" "+component.Version)
				} else {
					components = append(components, component.Name)
				}
			}
		}
		product := strings.Join(components, ", ")
		rows = append(rows, SpaceSearchResult{
			Host: item.URL, IP: item.IP, Port: item.Port, Protocol: item.Protocol, Domain: item.Domain,
			Title: item.WebTitle, Server: product, Country: item.Country, City: item.City,
			Banner: item.Banner, ICP: item.Number, Product: product, OS: item.OS,
		})
	}
	return SpaceSearchResponse{Provider: req.Provider, Query: req.Query, Page: req.Page, PageSize: req.PageSize, Total: result.Data.Total, List: rows}, nil
}

func (s *SpaceService) searchQuake(ctx context.Context, req SpaceSearchRequest, key SpaceEngineKey) (SpaceSearchResponse, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"query":        req.Query,
		"start":        (req.Page - 1) * req.PageSize,
		"size":         req.PageSize,
		"ignore_cache": false,
		"latest":       true,
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://quake.360.net/api/v3/search/quake_service", bytes.NewReader(payload))
	if err != nil {
		return SpaceSearchResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-QuakeToken", key.APIKey)
	body, err := s.doRequest(httpReq)
	if err != nil {
		return SpaceSearchResponse{}, err
	}
	var result struct {
		Code    spaceQuakeCode `json:"code"`
		Message string         `json:"message"`
		Data    spaceQuakeData `json:"data"`
		Meta    struct {
			Pagination struct {
				Total int `json:"total"`
			} `json:"pagination"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return SpaceSearchResponse{}, fmt.Errorf("Quake 响应解析失败: %w", err)
	}
	if !result.Code.Success() {
		return SpaceSearchResponse{}, fmt.Errorf("Quake 查询失败[%s]: %s", result.Code.String(), result.Message)
	}
	if result.Data.IsExhausted {
		return SpaceSearchResponse{}, fmt.Errorf("Quake API 配额已用尽")
	}
	rows := make([]SpaceSearchResult, 0, len(result.Data.Items))
	for _, item := range result.Data.Items {
		host := item.Service.HTTP.Host
		if host == "" {
			host = item.Hostname
		}
		if host == "" && item.Service.Name != "" {
			scheme := item.Service.Name
			if scheme == "http/ssl" || scheme == "https" {
				scheme = "https"
			} else if scheme == "http" {
				scheme = "http"
			}
			if scheme == "http" || scheme == "https" {
				host = fmt.Sprintf("%s://%s:%d", scheme, item.IP, item.Port)
			}
		}
		if host == "" {
			host = item.IP
		}
		product := item.Service.Product
		if product == "" {
			products := make([]string, 0, len(item.Components))
			for _, component := range item.Components {
				if component.ProductNameCN != "" {
					products = append(products, component.ProductNameCN)
				} else if component.ProductNameEN != "" {
					products = append(products, component.ProductNameEN)
				}
			}
			product = strings.Join(products, ", ")
		}
		rows = append(rows, SpaceSearchResult{
			Host: host, IP: item.IP, Port: item.Port, Protocol: item.Service.Name,
			Title: item.Service.HTTP.Title, Server: item.Service.HTTP.Server,
			Country: firstNonEmpty(item.Location.CountryCN, item.Location.CountryEN),
			City:    firstNonEmpty(item.Location.CityCN, item.Location.CityEN),
			Banner:  firstNonEmpty(item.Service.Response, item.Service.HTTP.Path),
			Product: product,
		})
	}
	return SpaceSearchResponse{Provider: req.Provider, Query: req.Query, Page: req.Page, PageSize: req.PageSize, Total: result.Meta.Pagination.Total, List: rows}, nil
}

func (s *SpaceService) searchShodan(ctx context.Context, req SpaceSearchRequest, key SpaceEngineKey) (SpaceSearchResponse, error) {
	apiURL := fmt.Sprintf(
		"https://api.shodan.io/shodan/host/search?key=%s&query=%s&page=%d&minify=false",
		url.QueryEscape(key.APIKey),
		url.QueryEscape(req.Query),
		req.Page,
	)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return SpaceSearchResponse{}, err
	}
	body, err := s.doRequest(httpReq)
	if err != nil {
		return SpaceSearchResponse{}, err
	}
	var result struct {
		Total   int `json:"total"`
		Matches []struct {
			IPStr     string   `json:"ip_str"`
			Port      int      `json:"port"`
			Transport string   `json:"transport"`
			Product   string   `json:"product"`
			OS        string   `json:"os"`
			Data      string   `json:"data"`
			Domains   []string `json:"domains"`
			Hostnames []string `json:"hostnames"`
			SSL       any      `json:"ssl"`
			HTTP      struct {
				Title  string `json:"title"`
				Server string `json:"server"`
				Host   string `json:"host"`
			} `json:"http"`
			Location struct {
				CountryName string `json:"country_name"`
				City        string `json:"city"`
			} `json:"location"`
			Shodan struct {
				Module string `json:"module"`
			} `json:"_shodan"`
		} `json:"matches"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return SpaceSearchResponse{}, fmt.Errorf("Shodan 响应解析失败: %w", err)
	}
	if result.Error != "" {
		return SpaceSearchResponse{}, fmt.Errorf("Shodan 查询失败: %s", result.Error)
	}
	rows := make([]SpaceSearchResult, 0, len(result.Matches))
	for _, item := range result.Matches {
		protocol := firstNonEmpty(item.Shodan.Module, item.Transport)
		host := item.HTTP.Host
		if host == "" && len(item.Hostnames) > 0 {
			host = item.Hostnames[0]
		}
		if host == "" {
			host = item.IPStr
		}
		if item.HTTP.Title != "" || item.HTTP.Server != "" || strings.Contains(protocol, "http") {
			scheme := "http"
			if item.Port == 443 || item.SSL != nil || strings.Contains(protocol, "ssl") || strings.Contains(protocol, "https") {
				scheme = "https"
			}
			host = fmt.Sprintf("%s://%s:%d", scheme, strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://"), item.Port)
			protocol = scheme
		}
		rows = append(rows, SpaceSearchResult{
			Host:     host,
			IP:       item.IPStr,
			Port:     item.Port,
			Protocol: protocol,
			Domain:   strings.Join(item.Domains, ", "),
			Title:    item.HTTP.Title,
			Server:   item.HTTP.Server,
			Country:  item.Location.CountryName,
			City:     item.Location.City,
			Banner:   item.Data,
			Product:  item.Product,
			OS:       item.OS,
		})
	}
	if req.PageSize > 0 && len(rows) > req.PageSize {
		rows = rows[:req.PageSize]
	}
	return SpaceSearchResponse{Provider: req.Provider, Query: req.Query, Page: req.Page, PageSize: req.PageSize, Total: result.Total, List: rows}, nil
}

func (s *SpaceService) searchZoomEye(ctx context.Context, req SpaceSearchRequest, key SpaceEngineKey) (SpaceSearchResponse, error) {
	queryBase64 := base64.StdEncoding.EncodeToString([]byte(req.Query))
	payload, _ := json.Marshal(map[string]interface{}{
		"qbase64":  queryBase64,
		"page":     req.Page,
		"pagesize": req.PageSize,
		"fields":   "ip,port,domain,url,title,service,product,os,banner,country.name,city.name,header.server.name",
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.zoomeye.ai/v2/search", bytes.NewReader(payload))
	if err != nil {
		return SpaceSearchResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("API-KEY", key.APIKey)
	body, err := s.doRequest(httpReq)
	if err != nil {
		return SpaceSearchResponse{}, err
	}
	var result struct {
		Code    int                      `json:"code"`
		Message string                   `json:"message"`
		Total   int                      `json:"total"`
		Data    []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return SpaceSearchResponse{}, fmt.Errorf("ZoomEye 响应解析失败: %w", err)
	}
	if result.Code != 0 && result.Code != 60000 {
		return SpaceSearchResponse{}, fmt.Errorf("ZoomEye 查询失败[%d]: %s", result.Code, result.Message)
	}
	rows := make([]SpaceSearchResult, 0, len(result.Data))
	for _, item := range result.Data {
		port := spaceIntFromAny(item["port"])
		ip := firstNonEmpty(spaceStringFromAny(item["ip"]), spaceStringFromAny(item["ip_str"]))
		protocol := firstNonEmpty(spaceStringFromAny(item["service"]), spaceStringFromAny(item["protocol"]))
		host := firstNonEmpty(spaceStringFromAny(item["url"]), spaceStringFromAny(item["domain"]))
		if host == "" && ip != "" {
			if strings.Contains(protocol, "http") {
				scheme := "http"
				if port == 443 || strings.Contains(protocol, "https") || strings.Contains(protocol, "ssl") {
					scheme = "https"
				}
				host = fmt.Sprintf("%s://%s:%d", scheme, ip, port)
			} else {
				host = ip
			}
		}
		rows = append(rows, SpaceSearchResult{
			Host:     host,
			IP:       ip,
			Port:     port,
			Protocol: protocol,
			Domain:   spaceStringFromAny(item["domain"]),
			Title:    spaceStringFromAny(item["title"]),
			Server:   firstNonEmpty(spaceStringFromAny(item["header.server.name"]), spaceStringFromAny(item["server"])),
			Country:  firstNonEmpty(spaceStringFromAny(item["country.name"]), spaceStringFromAny(item["country"])),
			City:     firstNonEmpty(spaceStringFromAny(item["city.name"]), spaceStringFromAny(item["city"])),
			Banner:   spaceStringFromAny(item["banner"]),
			Product:  spaceStringFromAny(item["product"]),
			OS:       spaceStringFromAny(item["os"]),
		})
	}
	return SpaceSearchResponse{Provider: req.Provider, Query: req.Query, Page: req.Page, PageSize: req.PageSize, Total: result.Total, List: rows}, nil
}

func (s *SpaceService) doRequest(req *http.Request) ([]byte, error) {
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateSpaceText(string(body), 300))
	}
	return body, nil
}

func scanSpaceEngineKey(scanner interface {
	Scan(dest ...interface{}) error
}, includeSecret bool) (SpaceEngineKey, error) {
	var item SpaceEngineKey
	var apiKey, secretKey, version, description, testStatus, testMessage, testAt, createdAt, updatedAt sql.NullString
	var enabled int
	if err := scanner.Scan(
		&item.ID, &item.Provider, &item.Name, &apiKey, &secretKey, &version, &enabled, &description,
		&testStatus, &testMessage, &testAt, &item.CreatedBy, &createdAt, &updatedAt,
	); err != nil {
		return SpaceEngineKey{}, err
	}
	if includeSecret {
		item.APIKey = apiKey.String
		item.SecretKey = secretKey.String
	}
	item.MaskedAPIKey = maskSpaceSecret(apiKey.String)
	item.MaskedSecretKey = maskSpaceSecret(secretKey.String)
	item.Version = version.String
	item.Enabled = enabled == 1
	item.Description = description.String
	item.LastTestStatus = testStatus.String
	item.LastTestMessage = testMessage.String
	item.LastTestAt = utils.FormatNullTimeStringForDisplay(testAt)
	item.CreatedAt = utils.FormatNullTimeStringForDisplay(createdAt)
	item.UpdatedAt = utils.FormatNullTimeStringForDisplay(updatedAt)
	return item, nil
}

func normalizeSpaceProvider(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "fofa":
		return SpaceProviderFOFA
	case "hunter", "qianxin":
		return SpaceProviderHunter
	case "quake", "360quake":
		return SpaceProviderQuake
	case "shodan":
		return SpaceProviderShodan
	case "zoomeye", "zoom-eye":
		return SpaceProviderZoomEye
	default:
		return ""
	}
}

func normalizeSpaceVersion(provider, value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if provider == SpaceProviderFOFA {
		if value == "v5" {
			return "v5"
		}
		if value == "v4" {
			return "v1"
		}
		return "v1"
	}
	return value
}

func normalizeSpacePagination(provider string, page, pageSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 10
	}
	limit := 100
	if provider == SpaceProviderFOFA {
		limit = 500
	}
	if provider == SpaceProviderShodan {
		limit = 100
	}
	if pageSize > limit {
		pageSize = limit
	}
	return page, pageSize
}

func validateSpaceSearchQuery(provider, query string) error {
	if provider == SpaceProviderFOFA && fofaRestrictedProductFieldPattern.MatchString(query) {
		return fmt.Errorf("FOFA 当前 Key 无权限搜索 product 字段，请改用 title、host、ip、domain、port 等普通字段")
	}
	return nil
}

func normalizeFofaCredentials(provider, apiKey, secretKey string) (string, string) {
	apiKey = strings.TrimSpace(apiKey)
	secretKey = strings.TrimSpace(secretKey)
	if provider != SpaceProviderFOFA || apiKey == "" {
		return apiKey, secretKey
	}
	for _, separator := range []string{":", "|"} {
		left, right, ok := strings.Cut(apiKey, separator)
		if !ok {
			continue
		}
		left = strings.TrimSpace(left)
		right = strings.TrimSpace(right)
		if left != "" && right != "" && strings.Contains(left, "@") {
			if secretKey == "" {
				secretKey = left
			}
			apiKey = right
			break
		}
	}
	return apiKey, secretKey
}

func getSpaceProviderLabel(provider string) string {
	switch provider {
	case SpaceProviderFOFA:
		return "FOFA"
	case SpaceProviderHunter:
		return "Hunter"
	case SpaceProviderQuake:
		return "Quake"
	case SpaceProviderShodan:
		return "Shodan"
	case SpaceProviderZoomEye:
		return "ZoomEye"
	default:
		return provider
	}
}

func defaultSpaceTestQuery(provider string) string {
	switch provider {
	case SpaceProviderQuake:
		return `ip:"1.1.1.1"`
	case SpaceProviderShodan:
		return `ip:1.1.1.1`
	default:
		return `ip="1.1.1.1"`
	}
}

func maskSpaceSecret(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return "****"
	}
	return value[:4] + "****" + value[len(value)-4:]
}

func truncateSpaceText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "... truncated ..."
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func spaceStringFromAny(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case []interface{}:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := spaceStringFromAny(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, ", ")
	case map[string]interface{}:
		if text := firstNonEmpty(spaceStringFromAny(typed["name"]), spaceStringFromAny(typed["value"]), spaceStringFromAny(typed["title"])); text != "" {
			return text
		}
		raw, _ := json.Marshal(typed)
		return string(raw)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func spaceIntFromAny(value interface{}) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		v, _ := typed.Int64()
		return int(v)
	case string:
		v, _ := strconv.Atoi(strings.TrimSpace(typed))
		return v
	default:
		v, _ := strconv.Atoi(spaceStringFromAny(value))
		return v
	}
}

type spaceQuakeCode struct {
	IntVal int
	StrVal string
	IsInt  bool
}

func (c *spaceQuakeCode) UnmarshalJSON(data []byte) error {
	var intVal int
	if err := json.Unmarshal(data, &intVal); err == nil {
		c.IntVal = intVal
		c.IsInt = true
		return nil
	}
	var strVal string
	if err := json.Unmarshal(data, &strVal); err == nil {
		c.StrVal = strVal
		if intVal, err := strconv.Atoi(strVal); err == nil {
			c.IntVal = intVal
			c.IsInt = true
		}
		return nil
	}
	return nil
}

func (c spaceQuakeCode) Success() bool {
	if c.IsInt {
		return c.IntVal == 0
	}
	return c.StrVal == "" || c.StrVal == "0"
}

func (c spaceQuakeCode) String() string {
	if c.IsInt {
		return strconv.Itoa(c.IntVal)
	}
	return c.StrVal
}

type spaceQuakeData struct {
	Items       []spaceQuakeItem
	IsExhausted bool
}

func (d *spaceQuakeData) UnmarshalJSON(data []byte) error {
	var items []spaceQuakeItem
	if err := json.Unmarshal(data, &items); err == nil {
		d.Items = items
		d.IsExhausted = false
		return nil
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err == nil {
		d.Items = []spaceQuakeItem{}
		d.IsExhausted = true
		return nil
	}
	d.Items = []spaceQuakeItem{}
	return nil
}

type spaceQuakeItem struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Hostname string `json:"hostname"`
	Service  struct {
		Name     string `json:"name"`
		Product  string `json:"product"`
		Response string `json:"response"`
		HTTP     struct {
			Title  string `json:"title"`
			Server string `json:"server"`
			Host   string `json:"host"`
			Path   string `json:"path"`
		} `json:"http"`
	} `json:"service"`
	Location struct {
		CountryCN string `json:"country_cn"`
		CountryEN string `json:"country_en"`
		CityCN    string `json:"city_cn"`
		CityEN    string `json:"city_en"`
	} `json:"location"`
	Components []struct {
		ProductNameCN string `json:"product_name_cn"`
		ProductNameEN string `json:"product_name_en"`
	} `json:"components"`
}
