package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// lureContent returns plausible, entirely fabricated content for a newly
// created decoy file, chosen by file name. Nothing here is real data: every
// secret is random and every host is loopback, so a lure can never leak
// anything. An empty "dump.sql.bak" is an immediate tell; realistic content
// invites the attacker to open, copy and use it.
func lureContent(name string) []byte {
	lower := strings.ToLower(name)
	secret := randHex(16)
	switch {
	case strings.Contains(lower, ".env"):
		return []byte(fmt.Sprintf(`APP_ENV=production
APP_KEY=base64:%s
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=app
DB_USERNAME=app
DB_PASSWORD=%s
REDIS_PASSWORD=%s
AWS_ACCESS_KEY_ID=AKIA%s
AWS_SECRET_ACCESS_KEY=%s
`, randB64(32), secret, randHex(12), strings.ToUpper(randHex(8)), randB64(30)))
	case strings.HasSuffix(lower, ".php"):
		return []byte(fmt.Sprintf(`<?php
// Backup of production configuration
define('DB_NAME', 'app');
define('DB_USER', 'app');
define('DB_PASSWORD', '%s');
define('DB_HOST', 'localhost');
define('AUTH_KEY', '%s');
`, secret, randHex(32)))
	case strings.Contains(lower, "pgpass"):
		return []byte(fmt.Sprintf("localhost:5432:*:postgres:%s\n", secret))
	case strings.Contains(lower, ".sql"), strings.HasSuffix(lower, ".bak"):
		return []byte(fmt.Sprintf(`-- MySQL dump 10.13  Distrib 8.0.36
-- Host: localhost    Database: app
-- Dump completed on %s

DROP TABLE IF EXISTS `+"`users`"+`;
CREATE TABLE `+"`users`"+` (
  `+"`id`"+` int NOT NULL AUTO_INCREMENT,
  `+"`email`"+` varchar(255) NOT NULL,
  `+"`password_hash`"+` varchar(255) NOT NULL,
  PRIMARY KEY (`+"`id`"+`)
);
INSERT INTO `+"`users`"+` VALUES (1,'admin@localhost','$2y$10$%s');
`, time.Now().UTC().Format("2006-01-02 15:04:05"), randB64(40)))
	case strings.Contains(lower, "vpn") || strings.Contains(lower, "wg") || strings.Contains(lower, "key"):
		return []byte(fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.66.0.2/32

[Peer]
PublicKey = %s
AllowedIPs = 10.66.0.0/24
Endpoint = 127.0.0.1:51820
`, randB64(32), randB64(32)))
	default:
		return []byte(fmt.Sprintf("# backup %s\ntoken=%s\n", time.Now().UTC().Format(time.RFC3339), secret))
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// deduper collapses bursts (one read fires OPEN plus several ACCESS events;
// one write fires MODIFY and CLOSE_WRITE) into one event per key per window.
type deduper struct {
	window time.Duration
	last   map[string]time.Time
}

func newDeduper(window time.Duration) *deduper {
	return &deduper{window: window, last: map[string]time.Time{}}
}

func (d *deduper) allow(key string, now time.Time) bool {
	if d.window <= 0 {
		return true
	}
	if t, ok := d.last[key]; ok && now.Sub(t) < d.window {
		return false
	}
	d.last[key] = now
	return true
}

func envInt(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return fallback
}
