package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

var ErrObjectNotFound = errors.New("object not found")

type R2ClientConfig struct {
	AccountID       string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	Region          string
	SignedUploadTTL time.Duration
	SignedReadTTL   time.Duration
	HTTPClient      *http.Client
}

type PresignedUpload struct {
	URL       string
	Method    string
	ObjectKey string
	ExpiresAt time.Time
	Headers   map[string]string
}

type PresignedRead struct {
	URL       string
	ExpiresAt time.Time
}

type ObjectMetadata struct {
	ObjectKey     string
	ContentType   string
	ContentLength int64
	ETag          string
	LastModified  time.Time
}

type R2Client struct {
	bucket          string
	signedUploadTTL time.Duration
	signedReadTTL   time.Duration
	s3Client        *s3.Client
	presignClient   *s3.PresignClient
}

func NewR2Client(cfg R2ClientConfig) (*R2Client, error) {
	accountID := strings.TrimSpace(cfg.AccountID)
	bucket := strings.TrimSpace(cfg.Bucket)
	accessKeyID := strings.TrimSpace(cfg.AccessKeyID)
	secretAccessKey := strings.TrimSpace(cfg.SecretAccessKey)
	region := strings.TrimSpace(cfg.Region)

	if accountID == "" || bucket == "" || accessKeyID == "" || secretAccessKey == "" {
		return nil, errors.New("r2 client requires account id, bucket, access key id, and secret access key")
	}

	if region == "" {
		region = "auto"
	}

	signedUploadTTL := cfg.SignedUploadTTL
	if signedUploadTTL <= 0 {
		signedUploadTTL = 10 * time.Minute
	}

	signedReadTTL := cfg.SignedReadTTL
	if signedReadTTL <= 0 {
		signedReadTTL = 10 * time.Minute
	}

	endpointURL := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)

	awsConfig, err := awscfg.LoadDefaultConfig(
		context.Background(),
		awscfg.WithRegion(region),
		awscfg.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws config for r2: %w", err)
	}

	if cfg.HTTPClient != nil {
		awsConfig.HTTPClient = cfg.HTTPClient
	}

	s3Client := s3.NewFromConfig(awsConfig, func(options *s3.Options) {
		options.UsePathStyle = true
		options.BaseEndpoint = aws.String(endpointURL)
	})

	return &R2Client{
		bucket:          bucket,
		signedUploadTTL: signedUploadTTL,
		signedReadTTL:   signedReadTTL,
		s3Client:        s3Client,
		presignClient:   s3.NewPresignClient(s3Client),
	}, nil
}

func (c *R2Client) CreatePresignedUploadURL(ctx context.Context, objectKey, contentType string, contentLength int64) (PresignedUpload, error) {
	trimmedKey := strings.Trim(strings.TrimSpace(objectKey), "/")
	if trimmedKey == "" {
		return PresignedUpload{}, errors.New("object key is required")
	}

	trimmedContentType := strings.TrimSpace(contentType)
	if trimmedContentType == "" {
		return PresignedUpload{}, errors.New("content type is required")
	}

	if contentLength <= 0 {
		return PresignedUpload{}, errors.New("content length is required")
	}

	presignedRequest, err := c.presignClient.PresignPutObject(
		ctx,
		&s3.PutObjectInput{
			Bucket:        aws.String(c.bucket),
			Key:           aws.String(trimmedKey),
			ContentType:   aws.String(trimmedContentType),
			ContentLength: aws.Int64(contentLength),
		},
		func(options *s3.PresignOptions) {
			options.Expires = c.signedUploadTTL
		},
	)
	if err != nil {
		return PresignedUpload{}, fmt.Errorf("presign put object: %w", err)
	}

	headers := make(map[string]string, len(presignedRequest.SignedHeader))
	for key, values := range presignedRequest.SignedHeader {
		if len(values) == 0 {
			continue
		}

		headers[key] = values[0]
	}

	headers["Content-Type"] = trimmedContentType
	headers["Content-Length"] = strconv.FormatInt(contentLength, 10)

	return PresignedUpload{
		URL:       presignedRequest.URL,
		Method:    presignedRequest.Method,
		ObjectKey: trimmedKey,
		ExpiresAt: time.Now().UTC().Add(c.signedUploadTTL),
		Headers:   headers,
	}, nil
}

func (c *R2Client) HeadObject(ctx context.Context, objectKey string) (ObjectMetadata, error) {
	trimmedKey := strings.Trim(strings.TrimSpace(objectKey), "/")
	if trimmedKey == "" {
		return ObjectMetadata{}, errors.New("object key is required")
	}

	output, err := c.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(trimmedKey),
	})
	if err != nil {
		if isNotFoundError(err) {
			return ObjectMetadata{}, ErrObjectNotFound
		}

		return ObjectMetadata{}, fmt.Errorf("head object: %w", err)
	}

	lastModified := time.Time{}
	if output.LastModified != nil {
		lastModified = output.LastModified.UTC()
	}

	return ObjectMetadata{
		ObjectKey:     trimmedKey,
		ContentType:   strings.TrimSpace(aws.ToString(output.ContentType)),
		ContentLength: aws.ToInt64(output.ContentLength),
		ETag:          strings.Trim(aws.ToString(output.ETag), "\""),
		LastModified:  lastModified,
	}, nil
}

func (c *R2Client) DeleteObject(ctx context.Context, objectKey string) error {
	trimmedKey := strings.Trim(strings.TrimSpace(objectKey), "/")
	if trimmedKey == "" {
		return nil
	}

	_, err := c.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(trimmedKey),
	})
	if err != nil {
		if isNotFoundError(err) {
			return nil
		}

		return fmt.Errorf("delete object: %w", err)
	}

	return nil
}

func (c *R2Client) ReadObjectPrefix(ctx context.Context, objectKey string, maxBytes int64) ([]byte, error) {
	trimmedKey := strings.Trim(strings.TrimSpace(objectKey), "/")
	if trimmedKey == "" {
		return nil, errors.New("object key is required")
	}

	if maxBytes <= 0 {
		maxBytes = 64
	}

	if maxBytes > 4096 {
		maxBytes = 4096
	}

	rangeHeader := fmt.Sprintf("bytes=0-%d", maxBytes-1)

	output, err := c.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(trimmedKey),
		Range:  aws.String(rangeHeader),
	})
	if err != nil {
		if isNotFoundError(err) {
			return nil, ErrObjectNotFound
		}

		return nil, fmt.Errorf("get object prefix: %w", err)
	}
	defer output.Body.Close()

	prefix, err := io.ReadAll(io.LimitReader(output.Body, maxBytes))
	if err != nil {
		return nil, fmt.Errorf("read object prefix: %w", err)
	}

	return prefix, nil
}

func (c *R2Client) CreatePresignedReadURL(ctx context.Context, objectKey string) (PresignedRead, error) {
	trimmedKey := strings.Trim(strings.TrimSpace(objectKey), "/")
	if trimmedKey == "" {
		return PresignedRead{}, errors.New("object key is required")
	}

	presignedRequest, err := c.presignClient.PresignGetObject(
		ctx,
		&s3.GetObjectInput{
			Bucket: aws.String(c.bucket),
			Key:    aws.String(trimmedKey),
		},
		func(options *s3.PresignOptions) {
			options.Expires = c.signedReadTTL
		},
	)
	if err != nil {
		return PresignedRead{}, fmt.Errorf("presign get object: %w", err)
	}

	return PresignedRead{
		URL:       presignedRequest.URL,
		ExpiresAt: time.Now().UTC().Add(c.signedReadTTL),
	}, nil
}

func isNotFoundError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NotFound", "NoSuchKey", "NoSuchBucket", "404":
			return true
		}
	}

	return false
}
