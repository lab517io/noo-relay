//go:build !unix

package store

func freeBytes(string) (int64, error) { return -1, nil }
