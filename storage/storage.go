package storage

import (
	gcs "cloud.google.com/go/storage"
	"context"
	"google.golang.org/api/option"
	"io/ioutil"
)

type Service interface {
	Put(ctx context.Context, path string, data []byte) error
	Get(ctx context.Context, path string) ([]byte, error)
}

type storage struct {
	bucketName string
	gcsClient  *gcs.Client
}

func NewStorage(ctx context.Context, userAgent string, bucketName string) (Service, error) {
	gcsClient, err := gcs.NewClient(ctx, option.WithUserAgent(userAgent), option.WithScopes(gcs.ScopeReadWrite))
	if err != nil {
		return nil, err
	}

	return &storage{bucketName: bucketName, gcsClient: gcsClient}, nil
}

func (s *storage) Put(ctx context.Context, path string, data []byte) error {
	bucket := s.gcsClient.Bucket(s.bucketName)

	object := bucket.Object(path).NewWriter(ctx)
	defer object.Close()

	_, err := object.Write(data)
	if err != nil {
		return err
	}

	return nil
}

func (s *storage) Get(ctx context.Context, path string) ([]byte, error) {
	bucket := s.gcsClient.Bucket(s.bucketName)

	object, err := bucket.Object(path).NewReader(ctx)
	if err != nil {
		return nil, err
	}

	defer object.Close()

	return ioutil.ReadAll(object)
}
