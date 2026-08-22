package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type MinIOConfig struct {
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	Bucket          string
	Region          string
	UseSSL          bool
	PublicURL       string
}

type Object struct {
	Body        io.ReadCloser
	ContentType string
}

type ObjectStore struct {
	client *s3.Client
	bucket string
}

var (
	defaultStore *ObjectStore
	storeMu      sync.RWMutex
)

func InitMinIO(config MinIOConfig) error {
	storeMu.Lock()
	defer storeMu.Unlock()

	store, err := newObjectStore(context.Background(), config)
	if err != nil {
		return err
	}
	defaultStore = store
	return nil
}

func TestMinIOConfig(config MinIOConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := newObjectStore(ctx, config)
	return err
}

func GetStore() *ObjectStore {
	storeMu.RLock()
	defer storeMu.RUnlock()
	return defaultStore
}

func Ready() bool {
	return GetStore() != nil
}

func Close() {
	storeMu.Lock()
	defaultStore = nil
	storeMu.Unlock()
}

func UploadFile(ctx context.Context, key, filePath, contentType string) error {
	store := GetStore()
	if store == nil {
		return fmt.Errorf("MinIO 未初始化")
	}
	return store.UploadFile(ctx, key, filePath, contentType)
}

func UploadBytes(ctx context.Context, key string, data []byte, contentType string) error {
	store := GetStore()
	if store == nil {
		return fmt.Errorf("MinIO 未初始化")
	}
	return store.UploadBytes(ctx, key, data, contentType)
}

func OpenObject(ctx context.Context, key string) (*Object, error) {
	store := GetStore()
	if store == nil {
		return nil, fmt.Errorf("MinIO 未初始化")
	}
	return store.OpenObject(ctx, key)
}

func (s *ObjectStore) UploadFile(ctx context.Context, key, filePath, contentType string) error {
	key = cleanObjectKey(key)
	if key == "" {
		return fmt.Errorf("对象 key 不能为空")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("打开待上传文件失败: %w", err)
	}
	defer file.Close()

	if contentType == "" {
		contentType = mime.TypeByExtension(strings.ToLower(filepath.Ext(filePath)))
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        file,
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("上传对象到 MinIO 失败: %w", err)
	}
	return nil
}

func (s *ObjectStore) UploadBytes(ctx context.Context, key string, data []byte, contentType string) error {
	key = cleanObjectKey(key)
	if key == "" {
		return fmt.Errorf("对象 key 不能为空")
	}
	if len(data) == 0 {
		return fmt.Errorf("对象内容不能为空")
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("上传对象到 MinIO 失败: %w", err)
	}
	return nil
}

func (s *ObjectStore) OpenObject(ctx context.Context, key string) (*Object, error) {
	key = cleanObjectKey(key)
	if key == "" {
		return nil, fmt.Errorf("对象 key 不能为空")
	}
	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("读取 MinIO 对象失败: %w", err)
	}
	contentType := ""
	if output.ContentType != nil {
		contentType = *output.ContentType
	}
	return &Object{Body: output.Body, ContentType: contentType}, nil
}

func (s *ObjectStore) ensureBucket(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.bucket)})
	if err == nil {
		return nil
	}
	if _, createErr := s.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(s.bucket)}); createErr != nil {
		return fmt.Errorf("确认或创建 MinIO 存储桶失败: %w", createErr)
	}
	_, err = s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.bucket)})
	if err != nil {
		return fmt.Errorf("MinIO 存储桶创建后仍不可访问: %w", err)
	}
	return nil
}

func newObjectStore(parent context.Context, config MinIOConfig) (*ObjectStore, error) {
	config = normalizeMinIOConfig(config)
	if err := validateMinIOConfig(config); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(config.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(config.AccessKeyID, config.SecretAccessKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("初始化 MinIO 客户端失败: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(config.Endpoint)
		options.UsePathStyle = true
	})

	store := &ObjectStore{client: client, bucket: config.Bucket}
	if err := store.ensureBucket(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

func normalizeMinIOConfig(config MinIOConfig) MinIOConfig {
	config.Endpoint = strings.TrimSpace(config.Endpoint)
	if config.Endpoint != "" && !strings.Contains(config.Endpoint, "://") {
		scheme := "http://"
		if config.UseSSL {
			scheme = "https://"
		}
		config.Endpoint = scheme + config.Endpoint
	}
	config.AccessKeyID = strings.TrimSpace(config.AccessKeyID)
	config.SecretAccessKey = strings.TrimSpace(config.SecretAccessKey)
	config.Bucket = strings.TrimSpace(config.Bucket)
	config.Region = strings.TrimSpace(config.Region)
	if config.Region == "" {
		config.Region = "us-east-1"
	}
	config.PublicURL = strings.TrimRight(strings.TrimSpace(config.PublicURL), "/")
	return config
}

func validateMinIOConfig(config MinIOConfig) error {
	var missing []string
	if config.Endpoint == "" {
		missing = append(missing, "Endpoint")
	}
	if config.AccessKeyID == "" {
		missing = append(missing, "AccessKey")
	}
	if config.SecretAccessKey == "" {
		missing = append(missing, "SecretKey")
	}
	if config.Bucket == "" {
		missing = append(missing, "Bucket")
	}
	if len(missing) > 0 {
		return fmt.Errorf("MinIO 配置不完整: %s", strings.Join(missing, "、"))
	}
	return nil
}

func cleanObjectKey(key string) string {
	key = strings.ReplaceAll(strings.TrimSpace(key), "\\", "/")
	key = strings.TrimPrefix(key, "/")
	parts := make([]string, 0)
	for _, part := range strings.Split(key, "/") {
		part = strings.TrimSpace(part)
		if part == "" || part == "." || part == ".." {
			continue
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "/")
}
