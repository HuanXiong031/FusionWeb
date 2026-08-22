package database

// Environment-backed connection types retained inside database to keep test helpers concise.
type DatabaseDriver string

const DriverPostgres DatabaseDriver = "postgres"

type DatabaseConfig struct {
	Driver       DatabaseDriver `json:"driver"`
	DSN          string         `json:"dsn"`
	MaxOpenConns int            `json:"maxOpenConns"`
	MaxIdleConns int            `json:"maxIdleConns"`
}

type RedisConfig struct {
	URL       string `json:"url"`
	Addr      string `json:"addr"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	DB        int    `json:"db"`
	KeyPrefix string `json:"keyPrefix"`
}

type MinIOConfig struct {
	Endpoint        string `json:"endpoint"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	UseSSL          bool   `json:"useSSL"`
	PublicURL       string `json:"publicUrl"`
}

var activeDriver = DriverPostgres

func CurrentDriver() DatabaseDriver { return activeDriver }
func IsPostgres() bool              { return activeDriver == DriverPostgres }
