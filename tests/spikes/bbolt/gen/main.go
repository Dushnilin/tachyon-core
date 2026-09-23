// F0 spike C (ADR-0005): reference bbolt writer/verifier.
// Content contract is shared with crates/core-experimental tests.
package main

import (
	"bytes"
	"fmt"
	"os"

	bolt "go.etcd.io/bbolt"
)

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 256)
	}
	return b
}

func write(path string) error {
	_ = os.Remove(path)
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucket([]byte("db-version"))
		if err != nil {
			return err
		}
		if err := meta.Put([]byte("value"), []byte("1")); err != nil {
			return err
		}
		cache, err := tx.CreateBucket([]byte("cache"))
		if err != nil {
			return err
		}
		if err := cache.Put([]byte("k1"), []byte("v1")); err != nil {
			return err
		}
		if err := cache.Put([]byte("k2"), pattern(3000)); err != nil {
			return err
		}
		sub, err := cache.CreateBucket([]byte("sub"))
		if err != nil {
			return err
		}
		return sub.Put([]byte("nested"), []byte("deep"))
	})
}

func verify(path string) error {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("db-version"))
		if meta == nil {
			return fmt.Errorf("missing bucket db-version")
		}
		if v := meta.Get([]byte("value")); !bytes.Equal(v, []byte("1")) {
			return fmt.Errorf("db-version/value = %q, want \"1\"", v)
		}
		cache := tx.Bucket([]byte("cache"))
		if cache == nil {
			return fmt.Errorf("missing bucket cache")
		}
		if v := cache.Get([]byte("k1")); !bytes.Equal(v, []byte("v1")) {
			return fmt.Errorf("cache/k1 = %q, want \"v1\"", v)
		}
		v2 := cache.Get([]byte("k2"))
		if !bytes.Equal(v2, pattern(3000)) {
			return fmt.Errorf("cache/k2 mismatch (len=%d)", len(v2))
		}
		sub := cache.Bucket([]byte("sub"))
		if sub == nil {
			return fmt.Errorf("missing bucket cache/sub")
		}
		if v := sub.Get([]byte("nested")); !bytes.Equal(v, []byte("deep")) {
			return fmt.Errorf("cache/sub/nested = %q, want \"deep\"", v)
		}
		return nil
	})
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s write|verify <path>\n", os.Args[0])
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "write":
		err = write(os.Args[2])
	case "verify":
		err = verify(os.Args[2])
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}
