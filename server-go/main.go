// luksmith-server — self-hosted escrow portal for luksmith agents (Go port).
//
// API- and database-compatible with server/luksmith_server.py.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
)

func main() {
	db := flag.String("db", "luksmith.db", "sqlite database path")
	bind := flag.String("bind", "127.0.0.1", "bind address")
	port := flag.Int("port", 8443, "listen port")
	adminToken := flag.String("admin-token", os.Getenv("LUKSMITH_ADMIN_TOKEN"),
		"admin bearer token (or env LUKSMITH_ADMIN_TOKEN)")
	enrollSecret := flag.String("enroll-secret", os.Getenv("LUKSMITH_ENROLL_SECRET"),
		"shared device-enrollment secret (or env LUKSMITH_ENROLL_SECRET)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate (PEM); omit only behind a reverse proxy")
	tlsKey := flag.String("tls-key", "", "TLS private key (PEM)")
	uiDir := flag.String("ui-dir", "", "static SPA directory served at / (built-in dashboard if unset)")
	flag.Parse()

	if *adminToken == "" || *enrollSecret == "" {
		fmt.Fprintln(os.Stderr, "error: --admin-token and --enroll-secret are required (flags or env)")
		os.Exit(2)
	}

	store, err := OpenStore(*db)
	if err != nil {
		log.Fatal(err)
	}
	handler := newHandler(store, *adminToken, *enrollSecret, *uiDir)
	addr := net.JoinHostPort(*bind, strconv.Itoa(*port))

	scheme := "http"
	if *tlsCert != "" && *tlsKey != "" {
		scheme = "https"
	} else if *bind != "127.0.0.1" && *bind != "::1" && *bind != "localhost" {
		fmt.Fprintln(os.Stderr, "WARNING: serving plain HTTP on a non-loopback address; "+
			"use --tls-cert/--tls-key or a TLS reverse proxy.")
	}
	fmt.Printf("luksmith-server on %s://%s:%d (db: %s)\n", scheme, *bind, *port, *db)
	if scheme == "https" {
		log.Fatal(http.ListenAndServeTLS(addr, *tlsCert, *tlsKey, handler))
	}
	log.Fatal(http.ListenAndServe(addr, handler))
}
