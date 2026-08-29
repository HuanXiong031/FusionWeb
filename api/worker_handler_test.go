package api

import (
	"strings"
	"testing"
)

func TestComposeQuotedEscapesDollar(t *testing.T) {
	got := composeQuoted("pa$$word")
	want := `"pa$$$$word"`
	if got != want {
		t.Fatalf("composeQuoted() = %q, want %q", got, want)
	}
}

func TestWorkerComposeTemplateUsesDotEnv(t *testing.T) {
	template := workerComposeTemplate()
	for _, fragment := range []string{"image: ${FUSIONWEB_IMAGE}", "env_file:", "- .env"} {
		if !strings.Contains(template, fragment) {
			t.Fatalf("workerComposeTemplate() missing %q", fragment)
		}
	}
}

func TestBuildWorkerBootstrapEnvIncludesExpectedKeys(t *testing.T) {
	state := workerInstallState{
		Image:          "registry.example/fusionweb-worker:0.1.0",
		Server:         "https://10.0.0.8:8988",
		WorkerKey:      "abc123",
		PGDSN:          "postgres://fusionweb:pass@10.0.0.8:5432/fusionweb?sslmode=disable",
		RedisAddr:      "10.0.0.8:6379",
		RedisPassword:  "redis-pass",
		RedisDB:        0,
		RedisPrefix:    "fusionweb",
		MinIOEndpoint:  "http://10.0.0.8:9000",
		MinIOAccessKey: "fusionweb",
		MinIOSecretKey: "minio-pass",
		MinIOBucket:    "fusionweb",
		MinIORegion:    "us-east-1",
		MinIOUseSSL:    false,
	}
	envText := buildWorkerBootstrapEnv(state)
	for _, fragment := range []string{
		"FUSIONWEB_IMAGE=registry.example/fusionweb-worker:0.1.0",
		"FUSIONWEB_SERVER=https://10.0.0.8:8988",
		"FUSIONWEB_KEY=abc123",
		"FUSIONWEB_PG_DSN=postgres://fusionweb:pass@10.0.0.8:5432/fusionweb?sslmode=disable",
		"FUSIONWEB_REDIS_ADDR=10.0.0.8:6379",
		"FUSIONWEB_MINIO_ENDPOINT=http://10.0.0.8:9000",
		"FUSIONWEB_INSECURE_TLS=true",
	} {
		if !strings.Contains(envText, fragment) {
			t.Fatalf("buildWorkerBootstrapEnv() missing %q", fragment)
		}
	}
}
