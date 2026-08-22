package bruteforce

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jlaffaye/ftp"
	"github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/ssh"
)

// ServiceType 定义服务类型
type ServiceType string

const (
	SSH        ServiceType = "ssh"
	MySQL      ServiceType = "mysql"
	Redis      ServiceType = "redis"
	FTP        ServiceType = "ftp"
	PostgreSQL ServiceType = "postgresql"
)

// Result 破解结果
type Result struct {
	Service  ServiceType
	Host     string
	Port     int
	Username string
	Password string
	Success  bool
	Error    error
}

// Options 破解选项
type Options struct {
	Host     string
	Port     int
	Service  ServiceType
	UserDict []string
	PassDict []string
	Timeout  time.Duration
}

// Crack 执行破解
func Crack(ctx context.Context, opts Options) <-chan Result {
	results := make(chan Result)

	go func() {
		defer close(results)

		// 规范化服务名称
		service := ServiceType(strings.ToLower(string(opts.Service)))
		// 处理 PostgreSQL 别名
		if service == "postgres" {
			service = PostgreSQL
		}

		// 准备用户列表
		users := opts.UserDict
		if len(users) == 0 {
			if service == Redis {
				users = []string{""}
			} else {
				users = []string{"root", "admin", "user", "test", "postgres", "mysql"}
			}
		}

		// 准备密码列表
		passwords := opts.PassDict
		if len(passwords) == 0 {
			passwords = []string{"", "123456", "password", "admin", "root"}
		}

		// 简单的连接检查（端口是否开放），避免无效尝试
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", opts.Host, opts.Port), opts.Timeout)
		if err != nil {
			return
		}
		conn.Close()

		for _, user := range users {
			for _, pass := range passwords {
				select {
				case <-ctx.Done():
					return
				default:
				}

				success, err := checkAuth(ctx, opts.Host, opts.Port, service, user, pass, opts.Timeout)
				if success {
					results <- Result{
						Service:  service,
						Host:     opts.Host,
						Port:     opts.Port,
						Username: user,
						Password: pass,
						Success:  true,
					}
					return // 找到一个成功匹配即停止（针对该服务）
				}
				// 可以在这里记录错误日志
				_ = err
			}
		}
	}()

	return results
}

func checkAuth(ctx context.Context, host string, port int, service ServiceType, user, pass string, timeout time.Duration) (bool, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	switch service {
	case SSH:
		return checkSSH(addr, user, pass, timeout)
	case MySQL:
		return checkMySQL(addr, user, pass, timeout)
	case Redis:
		return checkRedis(ctx, addr, pass, timeout)
	case FTP:
		return checkFTP(addr, user, pass, timeout)
	case PostgreSQL:
		return checkPostgreSQL(host, port, user, pass, timeout)
	default:
		return false, fmt.Errorf("unsupported service: %s", service)
	}
}

// checkSSH 检查 SSH 认证
func checkSSH(addr, user, pass string, timeout time.Duration) (bool, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return false, err
	}
	defer client.Close()
	return true, nil
}

// checkMySQL 检查 MySQL 认证
func checkMySQL(addr, user, pass string, timeout time.Duration) (bool, error) {
	// 构造 DSN: user:password@tcp(host:port)/dbname?timeout=xs
	cfg := mysql.Config{
		User:                 user,
		Passwd:               pass,
		Net:                  "tcp",
		Addr:                 addr,
		Timeout:              timeout,
		ReadTimeout:          timeout,
		WriteTimeout:         timeout,
		AllowNativePasswords: true,
	}
	dsn := cfg.FormatDSN()

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		return false, err
	}
	return true, nil
}

// checkRedis 检查 Redis 认证
func checkRedis(ctx context.Context, addr, pass string, timeout time.Duration) (bool, error) {
	opts := &redis.Options{
		Addr:        addr,
		Password:    pass,
		DialTimeout: timeout,
	}
	
	client := redis.NewClient(opts)
	defer client.Close()

	_, err := client.Ping(ctx).Result()
	if err != nil {
		return false, err
	}
	return true, nil
}

// checkFTP 检查 FTP 认证
func checkFTP(addr, user, pass string, timeout time.Duration) (bool, error) {
	c, err := ftp.Dial(addr, ftp.DialWithTimeout(timeout))
	if err != nil {
		return false, err
	}
	defer c.Quit()

	err = c.Login(user, pass)
	if err != nil {
		return false, err
	}
	
	// 尝试列出目录以确认权限（可选）
	// _, err = c.List("/")
	// if err != nil { return false, err }
	
	return true, nil
}

// checkPostgreSQL 检查 PostgreSQL 认证
func checkPostgreSQL(host string, port int, user, pass string, timeout time.Duration) (bool, error) {
	// 构造连接字符串
	// postgres://user:password@host:port/dbname?sslmode=disable
	// 注意：默认数据库通常是 postgres 或 user 同名
	// 这里尝试连接 'postgres' 数据库
	
	// 使用 pq.ParseURL 或者直接构造 connection string
	// "host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=%d"
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=%d",
		host, port, user, pass, int(timeout.Seconds()))
	
	// 如果 pq 包没有被显式导入用于 sql.Open，需要确保被 import
	_ = pq.Array(nil) // Dummy usage just in case

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return false, err
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		// 尝试 user 同名数据库
		if strings.Contains(err.Error(), "database") && strings.Contains(err.Error(), "does not exist") {
			connStr = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable connect_timeout=%d",
				host, port, user, pass, user, int(timeout.Seconds()))
			db2, err2 := sql.Open("postgres", connStr)
			if err2 != nil {
				return false, err2
			}
			defer db2.Close()
			if err3 := db2.Ping(); err3 == nil {
				return true, nil
			}
		}
		return false, err
	}
	return true, nil
}
