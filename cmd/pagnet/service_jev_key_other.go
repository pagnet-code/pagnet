//go:build !unix

package main

import (
	"errors"
	"os"
)

func validateJevKeyFileOwner(os.FileInfo) error {
	return errors.New("on this platform supply TYPESAFE_API_KEY through your local secret environment")
}

func validateJevProfileOwner(info os.FileInfo) error { return nil }
