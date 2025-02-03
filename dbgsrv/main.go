package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

func GenerateCertificate(cn string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	maxSerial := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 3650),
		Subject: pkix.Name{
			CommonName: cn,
		},
		Issuer: pkix.Name{
			CommonName: cn,
		},

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	bytes, err := x509.CreateCertificate(rand.Reader, &cert, &cert, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{bytes},
		PrivateKey:  priv,
	}, nil
}

func main() {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 8443})
	if err != nil {
		panic(err)
	}

	crt, err := GenerateCertificate("localhost")
	if err != nil {
		panic(err)
	}

	tr := quic.Transport{Conn: udpConn}
	ln, err := tr.Listen(&tls.Config{
		Certificates: []tls.Certificate{crt},
		NextProtos:   []string{"ag"},
	}, &quic.Config{})
	if err != nil {
		panic(err)
	}

	fmt.Println("Accepting...")
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			panic(err)
		}
		fmt.Println("Conn accepted")
		ctrl, err := conn.OpenStream()
		if err != nil {
			panic(err)
		}
		_, err = ctrl.Write([]byte("hello"))
		if err != nil {
			panic(err)
		}
		//_ = conn.CloseWithError(0, "")
	}
}
