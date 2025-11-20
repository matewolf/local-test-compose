/*
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: MIT OR GPL-2.0-only
 *
 * Licensed under the MIT license <LICENSE.MIT or https://opensource.org/licenses/MIT> or the GPLv2 license
 * <LICENSE.GPL or https://opensource.org/license/gpl-2-0>, at your option. This file may not be copied,
 * modified, or distributed except according to those terms.
 */

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var (
	httpPort, http2Port, tcpPort int
	tlsOn                        bool
	ipv4                         bool
)

func certificate() tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Rip Tides Labs"},
		},
		DNSNames:  []string{"localhost"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %s", err)
	}

	return cert
}

// logger middleware
func logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn := r.Context().Value(connKey{}).(net.Conn)

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			ti, err := GetsockoptTLSInfo(tcpConn)
			if err == nil {
				fmt.Printf("TLSInfo: %s\n", ti)
			} else {
				fmt.Printf("error: %#v\n", err)
			}
		} else if tlsConn, ok := conn.(*tls.Conn); ok {
			ti, err := GetsockoptTLSInfo(tlsConn.NetConn().(*net.TCPConn))
			if err == nil {
				fmt.Printf("TLSInfo: %s\n", ti)
			} else {
				fmt.Printf("error :%#v\n", err)
			}
		}

		log.Printf("%s %s %s %s", r.Proto, r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

type connKey struct{}

type TLSInfo struct {
	Enabled      bool
	MtlsType     [16]byte
	SpiffeID     [256]byte
	PeerSpiffeID [256]byte
	Alpn         [256]byte
}

func (t *TLSInfo) String() string {
	return fmt.Sprintf("Enabled: %t, MtlsType: %s, SpiffeID: %s, PeerSpiffeID: %s, Alpn: %s",
		t.Enabled,
		string(t.MtlsType[:]),
		string(t.SpiffeID[:]),
		string(t.PeerSpiffeID[:]),
		string(t.Alpn[:]))
}

func GetsockoptTLSInfo(tcpConn *net.TCPConn) (*TLSInfo, error) {
	if tcpConn == nil {
		return nil, fmt.Errorf("tcp conn is nil")
	}

	tlsInfo := TLSInfo{}
	size := unsafe.Sizeof(tlsInfo)

	var errno syscall.Errno

	fd, err := tcpConn.File()
	if err != nil {
		return nil, fmt.Errorf("failed to get file descriptor: %w", err)
	}

	_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd.Fd(), 0x1ed3, 0x1,
		uintptr(unsafe.Pointer(&tlsInfo)), uintptr(unsafe.Pointer(&size)), 0)

	if errno != 0 {
		return nil, fmt.Errorf("syscall failed. errno=%d", errno)
	}

	return &tlsInfo, nil
}

func startTCPServer() {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", tcpPort))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("TCP server listening on :%d", tcpPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 1024)
			n, _ := c.Read(buf)
			fmt.Printf("TCP received: %s\n", string(buf[:n]))
			c.Write([]byte("Hello from TCP server!\n"))
		}(conn)
	}
}

func startHTTP2Server() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 || (r.ProtoMajor == 1 && r.Header.Get("Upgrade") == "h2c" && r.Header.Get("HTTP2-Settings") != "") {
			io.WriteString(w, "Hello from HTTP/2 server!\n")
			return
		}

		http.Error(w, "Only HTTP/2 or HTTP/1.1 Upgrade to h2c supported", http.StatusHTTPVersionNotSupported)
	})

	h2s := &http2.Server{}
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", http2Port),
		Handler: h2c.NewHandler(logger(handler), h2s),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
	}

	log.Printf("HTTP/2 server listening on :%d", http2Port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func startHTTPServer() {
	handlerMux := http.NewServeMux()

	handlerMux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			// parse the multipart form in the request with a 1MB max
			err := r.ParseMultipartForm(1 << 20)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// write each uploaded file to disk
			for _, fheaders := range r.MultipartForm.File {
				for _, hdr := range fheaders {
					// open uploaded
					var infile multipart.File
					infile, err = hdr.Open()
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					// open destination file
					var outfile *os.File
					outfile, err = os.Create("./" + hdr.Filename)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					// save the data to the file
					var written int64
					written, err = io.Copy(outfile, infile)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					log.Printf("uploaded file: %s (%d bytes)", hdr.Filename, written)
				}
			}
			break
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	handlerMux.Handle("/", http.FileServer(http.Dir("./")))

	server := &http.Server{
		Handler: logger(handlerMux),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
	}

	network := "tcp"
	if ipv4 {
		network = "tcp4"
	}

	l, err := net.Listen(network, fmt.Sprintf(":%d", httpPort))
	if err != nil {
		log.Fatal(err)
	}

	if tlsOn {
		log.Println("HTTP server listening on https://" + fmt.Sprint(l.Addr()) + "...")

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{certificate()},
			NextProtos:   []string{"h2", "http/1.1"},
		}

		tlsListener := tls.NewListener(l, tlsConfig)
		err = server.Serve(tlsListener)
	} else {
		log.Println("HTTP server listening on http://" + fmt.Sprint(l.Addr()) + "...")
		err = server.Serve(l)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	flag.IntVar(&httpPort, "http-port", 8000, "HTTP server port")
	flag.IntVar(&http2Port, "http2-port", 8100, "HTTP2 server port")
	flag.IntVar(&tcpPort, "tcp-port", 8200, "TCP server port")
	flag.BoolVar(&tlsOn, "tls", false, "Enable TLS")
	flag.BoolVar(&ipv4, "4", false, "Force IPv4")
	flag.Parse()

	go startHTTPServer()
	go startHTTP2Server()
	go startTCPServer()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("Shutting down...")
}
