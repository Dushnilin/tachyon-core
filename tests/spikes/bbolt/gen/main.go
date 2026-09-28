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
		if err := sub.Put([]byte("nested"), []byte("deep")); err != nil {
			return err
		}
		// a value far larger than one page (overflow chain) and a bucket wide
		// enough to need branch pages behind its root
		if err := cache.Put([]byte("big"), pattern(20000)); err != nil {
			return err
		}
		wide, err := tx.CreateBucket([]byte("wide"))
		if err != nil {
			return err
		}
		for i := 0; i < 500; i++ {
			if err := wide.Put([]byte(fmt.Sprintf("key-%04d", i)), []byte{byte(i)}); err != nil {
				return err
			}
		}
		return nil
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
		if v := cache.Get([]byte("big")); !bytes.Equal(v, pattern(20000)) {
			return fmt.Errorf("cache/big mismatch (len=%d)", len(v))
		}
		wide := tx.Bucket([]byte("wide"))
		if wide == nil {
			return fmt.Errorf("missing bucket wide")
		}
		for i := 0; i < 500; i++ {
			key := []byte(fmt.Sprintf("key-%04d", i))
			if v := wide.Get(key); !bytes.Equal(v, []byte{byte(i)}) {
				return fmt.Errorf("wide/%s = %v, want %d", key, v, i)
			}
		}
		return nil
	})
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s write|verify|write-cache|verify-cache <path>\n", os.Args[0])
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "write":
		err = write(os.Args[2])
	case "verify":
		err = verify(os.Args[2])
	case "write-cache":
		err = writeCache(os.Args[2])
	case "verify-cache":
		err = verifyCache(os.Args[2])
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

// verifyCache checks a tachyon-core cache.db the way the reference reads it.
func verifyCache(path string) error {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		id := tx.Bucket([]byte("_id"))
		if id == nil {
			return fmt.Errorf("missing _id bucket")
		}
		if v := id.Get([]byte("cache_id")); len(v) == 0 {
			return fmt.Errorf("_id/cache_id is empty")
		}
		ruleSet := tx.Bucket([]byte("rule_set"))
		if ruleSet == nil {
			return fmt.Errorf("missing rule_set bucket")
		}
		// a small record and one spanning several bbolt pages
		if v := ruleSet.Get([]byte("geosite-ru")); len(v) == 0 {
			return fmt.Errorf("rule_set/geosite-ru missing")
		}
		big := ruleSet.Get([]byte("big"))
		if len(big) != 200000 {
			return fmt.Errorf("rule_set/big len=%d, want 200000", len(big))
		}
		for i := range big {
			if big[i] != byte(i%251) {
				return fmt.Errorf("rule_set/big byte %d = %d", i, big[i])
			}
		}
		if ruleSet.Get([]byte("removed")) != nil {
			return fmt.Errorf("rule_set/removed should be gone")
		}
		// the cursor must walk the bucket in key order
		c := ruleSet.Cursor()
		var keys []string
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			keys = append(keys, string(k))
		}
		if len(keys) != 2 || !bytes.Equal([]byte(keys[0]), []byte("big")) {
			return fmt.Errorf("rule_set keys = %v", keys)
		}
		return nil
	})
}

// writeCache produces the file the runtime is expected to read back.
func writeCache(path string) error {
	_ = os.Remove(path)
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		id, err := tx.CreateBucket([]byte("_id"))
		if err != nil {
			return err
		}
		if err := id.Put([]byte("cache_id"), []byte("go-cache-id")); err != nil {
			return err
		}
		ruleSet, err := tx.CreateBucket([]byte("rule_set"))
		if err != nil {
			return err
		}
		if err := ruleSet.Put([]byte("geosite-ru"), pattern(3000)); err != nil {
			return err
		}
		big := make([]byte, 200000)
		for i := range big {
			big[i] = byte(i % 251)
		}
		if err := ruleSet.Put([]byte("big"), big); err != nil {
			return err
		}
		return ruleSet.Put([]byte("removed"), []byte("gone"))
	})
}
