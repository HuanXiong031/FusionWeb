// Package database 负责 FusionWeb 的 PostgreSQL 数据库初始化与关闭。
//
// 当前模块以“当前版本新库初始化”为主，不再执行历史大版本迁移：
// - 读取环境变量中的 PostgreSQL、Redis、MinIO 连接配置。
// - 打开 PostgreSQL 并配置连接池。
// - 创建当前版本需要的表和索引。
// - 对当前版本新增的少量必要字段做幂等补齐，避免旧库启动后写入失败。
// - 首次启动时创建默认管理员账户。
//
// 注意：这里不会清理历史旧表，也不会执行复杂数据迁移。
package database

import (
	"FusionWeb/backend/config"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/runtimepath"
	"FusionWeb/backend/storage"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// DB 是应用级数据库连接池。
// 业务代码仍直接使用该变量，新增代码优先通过 GetDB 获取，便于后续替换为依赖注入。
var DB *sql.DB

const fallbackAdminPassword = "$X5_fK8T+&%=U@X*5j|f"

// GetDB 返回当前数据库连接池。
func GetDB() *sql.DB {
	return DB
}

// InitDatabase 初始化 PostgreSQL 与 Redis。
// 初始化失败会返回错误；默认管理员创建失败只记录告警，不阻塞应用启动。
func InitDatabase() error {
	if DB != nil {
		_ = Close()
	}
	cfg := config.Get()
	activeDriver = DriverPostgres
	if err := os.MkdirAll(getDataDir(), 0755); err != nil {
		return fmt.Errorf("创建数据目录失败: %w", err)
	}

	dbConfig := DatabaseConfig{Driver: DriverPostgres, DSN: cfg.PGDSN, MaxOpenConns: cfg.PGMaxOpen, MaxIdleConns: cfg.PGMaxIdle}
	db, err := openPostgresDatabase(dbConfig)
	if err != nil {
		return err
	}
	DB = db
	logger.Info("数据库驱动: %s", DriverPostgres)

	redisConfig := RedisConfig{Addr: cfg.RedisAddr, Password: cfg.RedisPassword, DB: cfg.RedisDB, KeyPrefix: cfg.RedisPrefix}
	if err := initRedis(redisConfig); err != nil {
		// Redis Stream 是分布式调度通道，但不应阻止 API 在单机降级模式下启动。
		// RedisClient 会保持 nil，TaskScheduler.publishOrQueue 会自动投递到本地 channel。
		logger.Warn("Redis 初始化失败，API 将使用本地任务队列: %v", err)
	} else {
		logger.Info("Redis 已连接: %s", redisDisplayAddress(redisConfig))
	}

	if err := storage.InitMinIO(storage.MinIOConfig{
		Endpoint: cfg.MinIOEndpoint, AccessKeyID: cfg.MinIOAccessKey, SecretAccessKey: cfg.MinIOSecretKey,
		Bucket: cfg.MinIOBucket, Region: cfg.MinIORegion, UseSSL: cfg.MinIOUseSSL, PublicURL: cfg.MinIOPublicURL,
	}); err != nil {
		closeRedis()
		_ = db.Close()
		DB = nil
		return err
	}
	logger.Info("MinIO 已连接: %s/%s", cfg.MinIOEndpoint, cfg.MinIOBucket)

	if err := createTables(); err != nil {
		closeRedis()
		_ = db.Close()
		DB = nil
		return fmt.Errorf("创建数据表失败: %w", err)
	}
	if err := initDefaultAdmin(); err != nil {
		logger.Warn("初始化默认管理员账户失败: %v", err)
	}
	return nil
}

func openPostgresDatabase(config DatabaseConfig) (*sql.DB, error) {
	if strings.TrimSpace(config.DSN) == "" {
		return nil, fmt.Errorf("PostgreSQL DSN 不能为空")
	}
	connector, err := openPostgresQuestionDB(config.DSN)
	if err != nil {
		return nil, fmt.Errorf("创建 PostgreSQL 连接器失败: %w", err)
	}
	db := sql.OpenDB(connector)
	maxOpen := config.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 50
	}
	maxIdle := config.MaxIdleConns
	if maxIdle <= 0 || maxIdle > maxOpen {
		maxIdle = 10
		if maxIdle > maxOpen {
			maxIdle = maxOpen
		}
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("连接 PostgreSQL 失败: %w", err)
	}
	return db, nil
}

func TestDatabaseConfig(c DatabaseConfig) error {
	db, err := openPostgresDatabase(c)
	if err != nil {
		return err
	}
	return db.Close()
}
func TestRedisConfig(c RedisConfig) error { return testRedisConfig(c) }
func TestMinIOConfig(c MinIOConfig) error {
	return storage.TestMinIOConfig(storage.MinIOConfig{Endpoint: c.Endpoint, AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, Bucket: c.Bucket, Region: c.Region, UseSSL: c.UseSSL, PublicURL: c.PublicURL})
}

// initDefaultAdmin 在没有管理员账号时创建初始管理员。
// 默认账号只用于首次进入系统，前端会要求用户修改默认密码。
func initDefaultAdmin() error {
	adminUsername, adminPassword := defaultAdminCredentials()
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&count)
	if err != nil {
		return fmt.Errorf("查询管理员账户失败: %w", err)
	}

	if count > 0 {
		logger.Info("管理员账户已存在，跳过创建默认管理员")
		logger.Info("默认管理员用户名: %s", adminUsername)
		logger.Info("默认管理员初始密码: %s", adminPassword)
		logger.Info("如已修改默认管理员密码，请使用修改后的密码登录")
	} else {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("密码加密失败: %w", err)
		}

		_, err = DB.Exec(`
			INSERT INTO users (username, password, email, real_name, role, status, must_change_password)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, adminUsername, string(hashedPassword), "admin@fusionscan.com", "系统管理员", "admin", "active", 1)

		if err != nil {
			return fmt.Errorf("创建默认管理员账户失败: %w", err)
		}

		logger.Info("默认管理员账户已创建")
		logger.Info("默认管理员用户名: %s", adminUsername)
		logger.Info("默认管理员初始密码: %s", adminPassword)
		logger.Info("请首次登录后修改默认管理员密码")
	}

	return nil
}

func defaultAdminCredentials() (string, string) {
	cfg := config.Get()
	username := strings.TrimSpace(cfg.BasicUser)
	if username == "" {
		username = "admin"
	}
	password := cfg.BasicPass
	if strings.TrimSpace(password) == "" {
		password = fallbackAdminPassword
	}
	return username, password
}

// getDataDir 返回统一的运行数据目录。
func getDataDir() string {
	return runtimepath.DataDir()
}

// createTables 创建当前版本需要的表和索引。
// 对已经存在的结果表，只补齐当前写入逻辑必需的新字段，不清理旧表。
func createTables() error {
	schemas := []string{
		// 扫描任务主表：保存任务目标、扫描参数、状态和通知配置。
		`CREATE TABLE IF NOT EXISTS task_config (
			task_id TEXT PRIMARY KEY,
			task_name TEXT NOT NULL,
			task_type TEXT DEFAULT 'web',
            target_input TEXT,
            port_range TEXT,
			scan_mode TEXT,
			scan_tool TEXT DEFAULT '',
			scan_options TEXT DEFAULT '{}',
			thread_count INTEGER,
			http_proxy TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			status TEXT,
			current_stage TEXT,
			user_id INTEGER DEFAULT 0,
			parent_task_id TEXT DEFAULT '',
			no_port_string TEXT DEFAULT '',
			skip_host_discovery INTEGER DEFAULT 0,
			no_icmp_ping INTEGER DEFAULT 0,
			tcp_ping INTEGER DEFAULT 0,
			ports_threshold INTEGER DEFAULT 65535,
			syn_scan_rate INTEGER DEFAULT 10000,
			port_scan_timeout INTEGER DEFAULT 3,
			web_timeout INTEGER DEFAULT 20,
			enable_screenshot INTEGER DEFAULT 0,
			web_link INTEGER DEFAULT 0,
			selected_dicts TEXT DEFAULT '[]',
			assigned_worker TEXT DEFAULT '',
			scan_all_pocs_when_no_fingerprint INTEGER DEFAULT 0,
			full_poc_scan INTEGER DEFAULT 0,
			enable_active_fingerprint INTEGER DEFAULT 0,
			ding_talk_token TEXT DEFAULT '',
			ding_talk_secret TEXT DEFAULT '',
			ding_talk_key_id INTEGER DEFAULT 0,
			completed_at TIMESTAMP
		)`,

		// 信息收集结果：端口、URL、协议等探测产物统一写入这里。
		`CREATE TABLE IF NOT EXISTS recon_results (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT NOT NULL,
			scan_scope TEXT,
			user_id INTEGER,
			result_type TEXT NOT NULL,
			target TEXT NOT NULL,
			source TEXT,
			extra_data TEXT,
			discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (task_id) REFERENCES task_config(task_id)
		)`,

		// 被动指纹规则：通过响应正文、响应头等内容匹配技术栈。
		`CREATE TABLE IF NOT EXISTS passive_fingerprints (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			rules TEXT,
			is_blacklisted INTEGER DEFAULT 0,
			is_enabled INTEGER DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by INTEGER,
			UNIQUE(name, created_by)
		)`,

		// 主动指纹规则：通过路径探测等主动请求方式识别技术栈。
		`CREATE TABLE IF NOT EXISTS active_fingerprints (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			rules TEXT,
			is_blacklisted INTEGER DEFAULT 0,
			is_enabled INTEGER DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by INTEGER,
			UNIQUE(name, created_by)
		)`,

		// 指纹识别结果：记录每个任务、目标命中的指纹名称和匹配信息。
		`CREATE TABLE IF NOT EXISTS fingerprint_results (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT NOT NULL,
			scan_scope TEXT,
			user_id INTEGER,
			target TEXT NOT NULL,
			fingerprint_name TEXT NOT NULL,
			matched_rules TEXT,
			identified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (task_id) REFERENCES task_config(task_id)
		)`,

		// 普通扫描任务漏洞结果：保存 Nuclei 等引擎的命中详情。
		`CREATE TABLE IF NOT EXISTS vuln_results (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT NOT NULL,
			scan_scope TEXT,
			user_id INTEGER,
			target TEXT NOT NULL,
			template_id TEXT,
			template_path TEXT,
			matcher_name TEXT,
			severity TEXT,
			name TEXT,
			author TEXT DEFAULT '',
			tags TEXT DEFAULT '',
			description TEXT,
			request TEXT,
			response TEXT,
			discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (task_id) REFERENCES task_config(task_id)
		)`,

		// 子域名扫描结果：只保存子域名模块产物，不混入 recon_results。
		`CREATE TABLE IF NOT EXISTS subdomain_results (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT NOT NULL,
			scan_scope TEXT,
			user_id INTEGER,
			domain TEXT NOT NULL,
			subdomain TEXT NOT NULL,
			ip_addresses TEXT DEFAULT '[]',
			cname TEXT DEFAULT '',
			source TEXT DEFAULT '',
			extra_data TEXT DEFAULT '{}',
			discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (task_id) REFERENCES task_config(task_id)
		)`,

		// 弱口令扫描结果：独立保存服务、账号、密码和目标信息。
		`CREATE TABLE IF NOT EXISTS weak_password_results (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT NOT NULL,
			scan_scope TEXT,
			user_id INTEGER,
			target TEXT NOT NULL,
			host TEXT NOT NULL,
			port INTEGER NOT NULL,
			service TEXT NOT NULL,
			username TEXT DEFAULT '',
			password TEXT DEFAULT '',
			severity TEXT DEFAULT 'high',
			extra_data TEXT DEFAULT '{}',
			discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (task_id) REFERENCES task_config(task_id)
		)`,

		// 目录扫描结果：独立保存目录爆破命中的 URL、路径和响应摘要。
		`CREATE TABLE IF NOT EXISTS directory_results (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT NOT NULL,
			scan_scope TEXT,
			user_id INTEGER,
			target TEXT NOT NULL,
			url TEXT NOT NULL,
			path TEXT DEFAULT '',
			status_code INTEGER DEFAULT 0,
			content_length INTEGER DEFAULT 0,
			content_type TEXT DEFAULT '',
			redirect_location TEXT DEFAULT '',
			source TEXT DEFAULT '',
			extra_data TEXT DEFAULT '{}',
			discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (task_id) REFERENCES task_config(task_id)
		)`,

		// JS 扫描结果：独立保存 JS 链接、接口、敏感信息等发现。
		`CREATE TABLE IF NOT EXISTS js_scan_results (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT NOT NULL,
			scan_scope TEXT,
			user_id INTEGER,
			target TEXT NOT NULL,
			result_type TEXT NOT NULL,
			value TEXT NOT NULL,
			source_url TEXT DEFAULT '',
			severity TEXT DEFAULT 'info',
			extra_data TEXT DEFAULT '{}',
			discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (task_id) REFERENCES task_config(task_id)
		)`,

		// 报告元数据：记录报告类型、文件路径和生成时间。
		// task_id 可能来自普通扫描或 POC 扫描，因此不绑定单一外键。
		`CREATE TABLE IF NOT EXISTS report_metadata (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT NOT NULL,
			report_type TEXT NOT NULL,
			file_path TEXT,
			generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// 任务日志：只保存能关联到任务 ID 的扫描日志，供任务日志页面查询。
		`CREATE TABLE IF NOT EXISTS task_logs (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT NOT NULL,
			level TEXT NOT NULL,
			stage TEXT,
			message TEXT NOT NULL,
			metadata TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// 扫描调试包：保存请求包、响应包和模板调试信息。
		`CREATE TABLE IF NOT EXISTS scan_debug_packets (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT,
			host TEXT,
			template_id TEXT,
			event_type TEXT NOT NULL,
			data TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// 登录审计日志：记录登录成功/失败、来源 IP、浏览器信息和 token 摘要。
		`CREATE TABLE IF NOT EXISTS login_logs (
			id BIGSERIAL PRIMARY KEY,
			username TEXT NOT NULL,
			ip_address TEXT,
			user_agent TEXT,
			login_result TEXT NOT NULL DEFAULT 'success',
			failure_reason TEXT,
			token_hash TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// 访问审计日志：记录后台 API 的访问来源、路径、状态码和耗时。
		`CREATE TABLE IF NOT EXISTS access_logs (
			id BIGSERIAL PRIMARY KEY,
			user_id INTEGER DEFAULT 0,
			username TEXT DEFAULT '',
			ip_address TEXT,
			method TEXT,
			path TEXT,
			query TEXT DEFAULT '',
			status_code INTEGER DEFAULT 0,
			latency_ms INTEGER DEFAULT 0,
			user_agent TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// 操作审计日志：记录会改变系统数据的新增、修改、删除等请求。
		`CREATE TABLE IF NOT EXISTS operation_logs (
			id BIGSERIAL PRIMARY KEY,
			user_id INTEGER DEFAULT 0,
			username TEXT DEFAULT '',
			ip_address TEXT,
			method TEXT,
			path TEXT,
			action TEXT DEFAULT '',
			target TEXT DEFAULT '',
			status_code INTEGER DEFAULT 0,
			latency_ms INTEGER DEFAULT 0,
			user_agent TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// 未授权访问日志：记录未登录、Token 缺失、Token 无效等被拒绝的后台访问。
		`CREATE TABLE IF NOT EXISTS unauthorized_access_logs (
			id BIGSERIAL PRIMARY KEY,
			ip_address TEXT,
			method TEXT,
			path TEXT,
			query TEXT DEFAULT '',
			status_code INTEGER DEFAULT 401,
			reason TEXT DEFAULT '',
			user_agent TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// 独立 POC 扫描任务：模板扫描页面使用，不依赖 task_config。
		`CREATE TABLE IF NOT EXISTS poc_scan_tasks (
			task_id TEXT PRIMARY KEY,
			task_name TEXT NOT NULL,
			targets TEXT NOT NULL,
			selected_pocs TEXT,
			status TEXT DEFAULT 'pending',
			progress REAL DEFAULT 0.0,
			found_vulns INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP,
			thread_count INTEGER DEFAULT 1000,
			http_proxy TEXT,
			rate_limit INTEGER DEFAULT 0,
			interactsh_url TEXT,
			interactsh_token TEXT,
			user_id INTEGER
		)`,

		// 独立 POC 扫描结果：保存模板扫描命中详情和原始数据包。
		`CREATE TABLE IF NOT EXISTS poc_scan_results (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT NOT NULL,
			scan_scope TEXT,
			user_id INTEGER,
			target TEXT NOT NULL,
			template_id TEXT,
			template_path TEXT,
			matcher_name TEXT,
			severity TEXT,
			name TEXT,
			author TEXT DEFAULT '',
			tags TEXT DEFAULT '',
			description TEXT,
			request TEXT,
			response TEXT,
			matched_at TEXT,
			extracted_results TEXT,
			metadata TEXT,
			discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (task_id) REFERENCES poc_scan_tasks(task_id) ON DELETE CASCADE
		)`,

		// 漏洞验证分组：手动漏洞验证记录的分类容器。
		`CREATE TABLE IF NOT EXISTS vuln_verify_group (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by INTEGER
		)`,

		// 手动漏洞验证：保存用户手动发包验证产生的漏洞记录。
		`CREATE TABLE IF NOT EXISTS manual_vuln_verify (
			id BIGSERIAL PRIMARY KEY,
			group_id INTEGER NOT NULL DEFAULT 0,
			name TEXT NOT NULL,
			target TEXT,
			severity TEXT DEFAULT 'info',
			request TEXT,
			response TEXT,
			status INTEGER DEFAULT 0,
			status_text TEXT,
			duration INTEGER DEFAULT 0,
			history TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			user_id INTEGER,
			FOREIGN KEY (group_id) REFERENCES vuln_verify_group(id) ON DELETE CASCADE
		)`,

		// 漏洞验证工作台标签：持久化每个用户的多标签发包状态。
		`CREATE TABLE IF NOT EXISTS vuln_verify_workbench_tabs (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			title TEXT NOT NULL,
			raw_packet TEXT,
			response_text TEXT,
			response_meta TEXT,
			force_https INTEGER DEFAULT 0,
			history_cursor INTEGER,
			sort_order INTEGER DEFAULT 0,
			active INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// 漏洞验证发包历史：按标签页记录历史请求、响应和发送元信息。
		`CREATE TABLE IF NOT EXISTS vuln_verify_workbench_history (
			id TEXT PRIMARY KEY,
			tab_id TEXT NOT NULL,
			user_id INTEGER NOT NULL,
			request TEXT,
			response TEXT,
			meta TEXT,
			sort_order INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (tab_id) REFERENCES vuln_verify_workbench_tabs(id) ON DELETE CASCADE
		)`,

		// 用户账号：保存登录凭据、角色、状态和首次登录改密标记。
		`CREATE TABLE IF NOT EXISTS users (
			id BIGSERIAL PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			email TEXT,
			real_name TEXT,
			avatar TEXT,
			role TEXT DEFAULT 'user',
			status TEXT DEFAULT 'active',
			must_change_password INTEGER DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP
		)`,

		// 扫描/指纹黑名单：当前主要保存指纹黑名单和通用黑名单分类。
		`CREATE TABLE IF NOT EXISTS blacklist (
			id BIGSERIAL PRIMARY KEY,
			category TEXT NOT NULL,
			item TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(category, item)
		)`,

		// 访问黑名单：限制指定 IP/域名访问 FusionWeb，可设置生效和过期时间。
		`CREATE TABLE IF NOT EXISTS access_blacklist (
			id BIGSERIAL PRIMARY KEY,
			category TEXT NOT NULL,
			item TEXT NOT NULL,
			starts_at TIMESTAMP,
			expires_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(category, item)
		)`,

		// 钉钉通知 Key：保存机器人凭据、启用状态和可触发的提醒范围。
		`CREATE TABLE IF NOT EXISTS dingtalk_keys (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			access_token TEXT NOT NULL,
			secret TEXT DEFAULT '',
			notify_blacklist_add INTEGER DEFAULT 0,
			notify_blacklist_remove INTEGER DEFAULT 0,
			notify_web_scan_complete INTEGER DEFAULT 0,
			notify_port_scan_complete INTEGER DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// 扫描配置：保存工具级配置，内容以 JSON 字符串存储。
		`CREATE TABLE IF NOT EXISTS scan_config (
			id BIGSERIAL PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			config TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// RTSP 字典：统一保存路径、用户名、密码三类 RTSP 扫描字典。
		`CREATE TABLE IF NOT EXISTS rtsp_dictionary (
			id BIGSERIAL PRIMARY KEY,
			dict_type TEXT NOT NULL,
			value TEXT NOT NULL,
			enabled INTEGER DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			created_by INTEGER DEFAULT 0,
			UNIQUE(dict_type, value)
		)`,

		// RTSP 扫描结果：保存命中的 RTSP 地址、凭据、路径和认证方式。
		`CREATE TABLE IF NOT EXISTS rtsp_scan_results (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT NOT NULL,
			target TEXT NOT NULL,
			host TEXT NOT NULL,
			port INTEGER DEFAULT 554,
			uri TEXT DEFAULT '',
			username TEXT DEFAULT '',
			password TEXT DEFAULT '',
			auth_method TEXT DEFAULT '',
			rtsp_url TEXT DEFAULT '',
			response TEXT DEFAULT '',
			status TEXT DEFAULT 'success',
			user_id INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// 扫描字典：保存目录扫描、弱口令、JS 关键词、子域名前缀等通用扫描字典。
		`CREATE TABLE IF NOT EXISTS scan_dictionaries (
			id BIGSERIAL PRIMARY KEY,
			dict_type TEXT NOT NULL,
			value TEXT NOT NULL,
			enabled INTEGER DEFAULT 1,
			description TEXT DEFAULT '',
			is_builtin INTEGER DEFAULT 0,
			created_by INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(dict_type, value)
		)`,

		// 空间测绘 API Key：保存 FOFA、Hunter、Quake 等在线资产引擎配置。
		`CREATE TABLE IF NOT EXISTS space_engine_keys (
			id BIGSERIAL PRIMARY KEY,
			provider TEXT NOT NULL,
			name TEXT NOT NULL,
			api_key TEXT NOT NULL,
			secret_key TEXT DEFAULT '',
			version TEXT DEFAULT '',
			enabled INTEGER DEFAULT 1,
			description TEXT DEFAULT '',
			last_test_status TEXT DEFAULT '',
			last_test_message TEXT DEFAULT '',
			last_test_at TIMESTAMP,
			created_by INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// 空间测绘在线搜索结果：记录用户通过第三方空间引擎查询到的标准化资产。
		`CREATE TABLE IF NOT EXISTS space_search_results (
			id BIGSERIAL PRIMARY KEY,
			provider TEXT NOT NULL,
			query TEXT NOT NULL,
			user_id INTEGER DEFAULT 0,
			host TEXT DEFAULT '',
			ip TEXT DEFAULT '',
			port INTEGER DEFAULT 0,
			protocol TEXT DEFAULT '',
			domain TEXT DEFAULT '',
			title TEXT DEFAULT '',
			server TEXT DEFAULT '',
			country TEXT DEFAULT '',
			city TEXT DEFAULT '',
			banner TEXT DEFAULT '',
			icp TEXT DEFAULT '',
			product TEXT DEFAULT '',
			os TEXT DEFAULT '',
			raw_data TEXT DEFAULT '{}',
			searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	// 索引创建失败不阻断启动，但要记录日志，方便定位查询变慢或字段缺失问题。
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_task_status ON task_config(status)",
		"CREATE INDEX IF NOT EXISTS idx_task_created ON task_config(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_task_user ON task_config(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_recon_task ON recon_results(task_id)",
		"CREATE INDEX IF NOT EXISTS idx_recon_user ON recon_results(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_recon_scope ON recon_results(scan_scope)",
		"CREATE INDEX IF NOT EXISTS idx_recon_type ON recon_results(result_type)",
		"CREATE INDEX IF NOT EXISTS idx_fingerprint_task ON fingerprint_results(task_id)",
		"CREATE INDEX IF NOT EXISTS idx_fingerprint_user ON fingerprint_results(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_fingerprint_scope ON fingerprint_results(scan_scope)",
		"CREATE INDEX IF NOT EXISTS idx_vuln_task ON vuln_results(task_id)",
		"CREATE INDEX IF NOT EXISTS idx_vuln_user ON vuln_results(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_vuln_scope ON vuln_results(scan_scope)",
		"CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vuln_results(severity)",
		"CREATE INDEX IF NOT EXISTS idx_subdomain_task ON subdomain_results(task_id)",
		"CREATE INDEX IF NOT EXISTS idx_subdomain_user ON subdomain_results(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_subdomain_domain ON subdomain_results(domain)",
		"CREATE INDEX IF NOT EXISTS idx_weak_password_task ON weak_password_results(task_id)",
		"CREATE INDEX IF NOT EXISTS idx_weak_password_user ON weak_password_results(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_weak_password_service ON weak_password_results(service)",
		"CREATE INDEX IF NOT EXISTS idx_directory_task ON directory_results(task_id)",
		"CREATE INDEX IF NOT EXISTS idx_directory_user ON directory_results(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_directory_status ON directory_results(status_code)",
		"CREATE INDEX IF NOT EXISTS idx_js_scan_task ON js_scan_results(task_id)",
		"CREATE INDEX IF NOT EXISTS idx_js_scan_user ON js_scan_results(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_js_scan_type ON js_scan_results(result_type)",
		"CREATE INDEX IF NOT EXISTS idx_poc_task_status ON poc_scan_tasks(status)",
		"CREATE INDEX IF NOT EXISTS idx_poc_task_created ON poc_scan_tasks(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_poc_result_task ON poc_scan_results(task_id)",
		"CREATE INDEX IF NOT EXISTS idx_poc_result_user ON poc_scan_results(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_poc_result_scope ON poc_scan_results(scan_scope)",
		"CREATE INDEX IF NOT EXISTS idx_poc_result_severity ON poc_scan_results(severity)",
		"CREATE INDEX IF NOT EXISTS idx_poc_result_target ON poc_scan_results(target)",
		"CREATE INDEX IF NOT EXISTS idx_poc_result_template ON poc_scan_results(template_id)",
		"CREATE INDEX IF NOT EXISTS idx_poc_result_discovered ON poc_scan_results(discovered_at)",
		"CREATE INDEX IF NOT EXISTS idx_vuln_verify_group_created_by ON vuln_verify_group(created_by)",
		"CREATE INDEX IF NOT EXISTS idx_manual_vuln_user ON manual_vuln_verify(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_vuln_verify_workbench_user ON vuln_verify_workbench_tabs(user_id, sort_order)",
		"CREATE INDEX IF NOT EXISTS idx_vuln_verify_history_tab ON vuln_verify_workbench_history(tab_id, sort_order)",
		"CREATE INDEX IF NOT EXISTS idx_vuln_verify_history_user ON vuln_verify_workbench_history(user_id, created_at)",
		"CREATE INDEX IF NOT EXISTS idx_blacklist_category ON blacklist(category)",
		"CREATE INDEX IF NOT EXISTS idx_access_blacklist_category ON access_blacklist(category)",
		"CREATE INDEX IF NOT EXISTS idx_access_blacklist_starts ON access_blacklist(starts_at)",
		"CREATE INDEX IF NOT EXISTS idx_access_blacklist_expires ON access_blacklist(expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_dingtalk_keys_enabled ON dingtalk_keys(enabled)",
		"CREATE INDEX IF NOT EXISTS idx_login_logs_created ON login_logs(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_login_logs_ip ON login_logs(ip_address)",
		"CREATE INDEX IF NOT EXISTS idx_access_logs_created ON access_logs(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_access_logs_ip ON access_logs(ip_address)",
		"CREATE INDEX IF NOT EXISTS idx_access_logs_path ON access_logs(path)",
		"CREATE INDEX IF NOT EXISTS idx_operation_logs_created ON operation_logs(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_operation_logs_user ON operation_logs(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_operation_logs_path ON operation_logs(path)",
		"CREATE INDEX IF NOT EXISTS idx_unauthorized_access_logs_created ON unauthorized_access_logs(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_unauthorized_access_logs_ip ON unauthorized_access_logs(ip_address)",
		"CREATE INDEX IF NOT EXISTS idx_unauthorized_access_logs_path ON unauthorized_access_logs(path)",
		"CREATE INDEX IF NOT EXISTS idx_task_logs_task_created ON task_logs(task_id, created_at)",
		"CREATE INDEX IF NOT EXISTS idx_task_logs_level ON task_logs(level)",
		"CREATE INDEX IF NOT EXISTS idx_scan_debug_packets_task_created ON scan_debug_packets(task_id, created_at)",
		"CREATE INDEX IF NOT EXISTS idx_scan_debug_packets_event_type ON scan_debug_packets(event_type)",
		"CREATE INDEX IF NOT EXISTS idx_rtsp_dictionary_type ON rtsp_dictionary(dict_type)",
		"CREATE INDEX IF NOT EXISTS idx_rtsp_dictionary_enabled ON rtsp_dictionary(enabled)",
		"CREATE INDEX IF NOT EXISTS idx_rtsp_results_task ON rtsp_scan_results(task_id)",
		"CREATE INDEX IF NOT EXISTS idx_rtsp_results_user ON rtsp_scan_results(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_rtsp_results_host ON rtsp_scan_results(host)",
		"CREATE INDEX IF NOT EXISTS idx_rtsp_results_created ON rtsp_scan_results(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_scan_dictionary_type ON scan_dictionaries(dict_type)",
		"CREATE INDEX IF NOT EXISTS idx_scan_dictionary_enabled ON scan_dictionaries(enabled)",
		"CREATE INDEX IF NOT EXISTS idx_scan_dictionary_builtin ON scan_dictionaries(is_builtin)",
		"CREATE INDEX IF NOT EXISTS idx_space_engine_provider ON space_engine_keys(provider)",
		"CREATE INDEX IF NOT EXISTS idx_space_engine_user ON space_engine_keys(created_by)",
		"CREATE INDEX IF NOT EXISTS idx_space_engine_enabled ON space_engine_keys(enabled)",
		"CREATE INDEX IF NOT EXISTS idx_space_search_provider ON space_search_results(provider)",
		"CREATE INDEX IF NOT EXISTS idx_space_search_user ON space_search_results(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_space_search_ip ON space_search_results(ip)",
		"CREATE INDEX IF NOT EXISTS idx_space_search_time ON space_search_results(searched_at)",
	}

	if err := executeRequiredStatements("创建表", schemas); err != nil {
		return err
	}

	if err := ensureRTSPDictionarySchema(); err != nil {
		return err
	}

	if err := ensureTaskConfigColumns(); err != nil {
		return err
	}

	if err := ensureResultMetadataColumns(); err != nil {
		return err
	}

	for _, index := range indexes {
		if _, err := DB.Exec(index); err != nil {
			logger.Warn("创建索引失败: %v, SQL: %s", err, previewSQL(index))
		}
	}

	return nil
}

func ensureTaskConfigColumns() error {
	columns := []struct {
		column     string
		definition string
	}{
		{"scan_tool", "scan_tool TEXT DEFAULT ''"},
		{"scan_options", "scan_options TEXT DEFAULT '{}'"},
		{"selected_dicts", "selected_dicts TEXT DEFAULT '[]'"},
		{"web_timeout", "web_timeout INTEGER DEFAULT 20"},
		{"enable_screenshot", "enable_screenshot INTEGER DEFAULT 0"},
		{"assigned_worker", "assigned_worker TEXT DEFAULT ''"},
	}

	for _, item := range columns {
		exists, err := tableColumnExists("task_config", item.column)
		if err != nil {
			return fmt.Errorf("检查字段失败 task_config.%s: %w", item.column, err)
		}
		if exists {
			continue
		}
		if _, err := DB.Exec(fmt.Sprintf("ALTER TABLE task_config ADD COLUMN %s", item.definition)); err != nil {
			return fmt.Errorf("添加字段失败 task_config.%s: %w", item.column, err)
		}
	}
	return nil
}

func ensureResultMetadataColumns() error {
	columns := []struct {
		table      string
		column     string
		definition string
	}{
		{"vuln_results", "author", "author TEXT DEFAULT ''"},
		{"vuln_results", "tags", "tags TEXT DEFAULT ''"},
		{"poc_scan_results", "author", "author TEXT DEFAULT ''"},
		{"poc_scan_results", "tags", "tags TEXT DEFAULT ''"},
	}

	for _, item := range columns {
		exists, err := tableColumnExists(item.table, item.column)
		if err != nil {
			return fmt.Errorf("检查字段失败 %s.%s: %w", item.table, item.column, err)
		}
		if exists {
			continue
		}
		if _, err := DB.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", item.table, item.definition)); err != nil {
			return fmt.Errorf("添加字段失败 %s.%s: %w", item.table, item.column, err)
		}
	}
	return nil
}

func ensureRTSPDictionarySchema() error {
	return nil
}

func tableColumnExists(tableName, columnName string) (bool, error) {
	var count int
	err := DB.QueryRow(`
		SELECT COUNT(*)
		  FROM information_schema.columns
		 WHERE table_schema = current_schema()
		   AND table_name = $1
		   AND column_name = $2
	`, tableName, columnName).Scan(&count)
	return count > 0, err
}

func executeRequiredStatements(action string, statements []string) error {
	for _, statement := range statements {
		if _, err := DB.Exec(statement); err != nil {
			logger.Error("%s失败: %v, SQL: %s", action, err, previewSQL(statement))
			return fmt.Errorf("%s失败: %w", action, err)
		}
	}
	return nil
}

func previewSQL(sql string) string {
	const maxPreviewLength = 100
	if len(sql) <= maxPreviewLength {
		return sql
	}
	return sql[:maxPreviewLength] + "..."
}

// databaseChinaLocation 返回数据库时间使用的中国时区。
// 加载系统时区失败时回退到固定 UTC+8，避免时间格式化失败。
func databaseChinaLocation() *time.Location {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		return time.FixedZone("CST", 8*3600)
	}
	return loc
}

// checkWritePermission 通过创建临时文件验证目录是否可写。
func checkWritePermission(dir string) error {
	testFile := filepath.Join(dir, ".write_test")
	defer os.Remove(testFile)

	file, err := os.Create(testFile)
	if err != nil {
		return fmt.Errorf("无法创建测试文件: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("无法关闭测试文件: %w", err)
	}
	return nil
}

// checkFileWritePermission 通过读写方式打开文件验证数据库文件是否可写。
func checkFileWritePermission(filePath string) error {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0666)
	if err != nil {
		return fmt.Errorf("无法以读写模式打开文件: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("无法关闭文件: %w", err)
	}
	return nil
}

// fixFilePermissions 尝试给数据库相关文件补充读写权限。
// 主要用于处理 Windows 下文件被标记为只读、或拷贝后权限异常的情况。
func fixFilePermissions(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("无法获取文件信息: %w", err)
	}

	mode := info.Mode()
	if mode&0200 == 0 {
		newMode := mode | 0200 | 0400
		if err := os.Chmod(filePath, newMode); err != nil {
			return fmt.Errorf("无法修改文件权限: %w", err)
		}
		logger.Info("已修复数据库文件权限: %s", filePath)
	}

	return nil
}

// Close 安全关闭数据库和 Redis 连接。
func Close() error {
	closeRedis()
	storage.Close()
	if DB == nil {
		return nil
	}

	err := DB.Close()
	if err != nil {
		return fmt.Errorf("关闭数据库连接失败: %w", err)
	}

	DB = nil
	return nil
}
