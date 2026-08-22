package database

import (
	"FusionWeb/backend/config"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var RedisClient *redis.Client

func GetRedis() *redis.Client { return RedisClient }
func RedisEnabled() bool      { return RedisClient != nil }

func RedisKey(parts ...string) string {
	prefix := strings.Trim(config.Get().RedisPrefix, ": ")
	if prefix == "" {
		prefix = "fusionweb"
	}
	cleaned := []string{prefix}
	for _, part := range parts {
		if p := strings.Trim(part, ": "); p != "" {
			cleaned = append(cleaned, p)
		}
	}
	return strings.Join(cleaned, ":")
}

func initRedis(c RedisConfig) error {
	closeRedis()
	opts, err := redisOptions(c)
	if err != nil {
		return err
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return fmt.Errorf("连接 Redis 失败: %w", err)
	}
	RedisClient = client
	return nil
}
func testRedisConfig(c RedisConfig) error {
	opts, err := redisOptions(c)
	if err != nil {
		return err
	}
	client := redis.NewClient(opts)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("连接 Redis 失败: %w", err)
	}
	return nil
}
func redisOptions(c RedisConfig) (*redis.Options, error) {
	if strings.TrimSpace(c.URL) != "" {
		parsed, err := redis.ParseURL(c.URL)
		if err != nil {
			return nil, fmt.Errorf("解析 Redis URL 失败: %w", err)
		}
		return parsed, nil
	}
	if strings.TrimSpace(c.Addr) == "" {
		return nil, fmt.Errorf("Redis 地址不能为空")
	}
	return &redis.Options{Addr: strings.TrimSpace(c.Addr), Username: c.Username, Password: c.Password, DB: c.DB}, nil
}
func redisDisplayAddress(c RedisConfig) string {
	if strings.TrimSpace(c.URL) != "" {
		return "redis-url"
	}
	return strings.TrimSpace(c.Addr)
}
func closeRedis() {
	if RedisClient != nil {
		_ = RedisClient.Close()
		RedisClient = nil
	}
}
