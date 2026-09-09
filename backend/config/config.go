// Package config loads FusionWeb runtime configuration exclusively from environment variables.
package config

import (
	"os"
	"strconv"
	"strings"
	"sync"
)

type Config struct {
	Port          int
	BasicAuth     bool
	BasicUser     string
	BasicPass     string
	JWTSecret     string
	EncryptionKey string
	WebTitle      string
	DataDir       string

	PGDSN     string
	PGMaxOpen int
	PGMaxIdle int

	RedisAddr     string
	RedisPassword string
	RedisDB       int
	RedisPrefix   string

	MinIOEndpoint  string
	MinIOAccessKey string
	MinIOSecretKey string
	MinIOBucket    string
	MinIORegion    string
	MinIOUseSSL    bool
	MinIOPublicURL string
	PublicURL      string

	WorkerKey     string
	LocalConsumer bool
}

var (
	once     sync.Once
	instance *Config
)

func Get() *Config {
	once.Do(func() {
		instance = &Config{
			Port:           envInt("FUSIONWEB_PORT", 8082),
			BasicAuth:      envBool("FUSIONWEB_BASIC_AUTH", true),
			BasicUser:      env("FUSIONWEB_BASIC_USER", "admin"),
			BasicPass:      env("FUSIONWEB_BASIC_PASS", ""),
			JWTSecret:      env("FUSIONWEB_JWT_SECRET", ""),
			EncryptionKey:  env("FUSIONWEB_ENCRYPTION_KEY", ""),
			WebTitle:       env("FUSIONWEB_TITLE", "FusionWeb"),
			DataDir:        env("FUSIONWEB_DATA_DIR", ""),
			PGDSN:          env("FUSIONWEB_PG_DSN", "postgres://fusionweb:fusionweb@localhost:5432/fusionweb?sslmode=disable"),
			PGMaxOpen:      envInt("FUSIONWEB_PG_MAX_OPEN", 50),
			PGMaxIdle:      envInt("FUSIONWEB_PG_MAX_IDLE", 10),
			RedisAddr:      env("FUSIONWEB_REDIS_ADDR", "localhost:6379"),
			RedisPassword:  env("FUSIONWEB_REDIS_PASSWORD", ""),
			RedisDB:        envInt("FUSIONWEB_REDIS_DB", 0),
			RedisPrefix:    env("FUSIONWEB_REDIS_PREFIX", "fusionweb"),
			MinIOEndpoint:  env("FUSIONWEB_MINIO_ENDPOINT", "http://localhost:9000"),
			MinIOAccessKey: env("FUSIONWEB_MINIO_ACCESS_KEY", "minioadmin"),
			MinIOSecretKey: env("FUSIONWEB_MINIO_SECRET_KEY", "minioadmin"),
			MinIOBucket:    env("FUSIONWEB_MINIO_BUCKET", "fusionweb"),
			MinIORegion:    env("FUSIONWEB_MINIO_REGION", "us-east-1"),
			MinIOUseSSL:    envBool("FUSIONWEB_MINIO_USE_SSL", false),
			MinIOPublicURL: env("FUSIONWEB_MINIO_PUBLIC_URL", ""),
			PublicURL:      env("FUSIONWEB_PUBLIC_URL", ""),
			WorkerKey:      env("FUSIONWEB_WORKER_KEY", ""),
			LocalConsumer:  envBool("FUSIONWEB_LOCAL_CONSUMER", true),
		}
	})
	return instance
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
func envInt(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}
func envBool(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
