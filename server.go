package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"
)

const (
	readTimeout   = 30 * time.Second
	writeTimeout  = 10 * time.Second
	acceptTimeout = 1 * time.Second
	maxTokenLen   = 1024
	bufferSize    = 16 * 1024
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 4 {
		return fmt.Errorf("usage: %s <bind_ip> <port> <token>", os.Args[0])
	}

	bindIP := os.Args[1]
	port := os.Args[2]
	token := os.Args[3]

	if err := validateToken(token); err != nil {
		return err
	}

	addr := net.JoinHostPort(bindIP, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Fprintln(os.Stderr, "server listening on", addr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	for {
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			_ = tcpListener.SetDeadline(time.Now().Add(acceptTimeout))
		}

		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					break
				}
				continue
			}
			return err
		}

		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}

		if err := performHandshakeServer(conn, token); err != nil {
			fmt.Fprintf(os.Stderr, "handshake failed from %s: %v\n", conn.RemoteAddr(), err)
			_ = conn.Close()
			continue
		}

		shutdownRequested, err := runSession(ctx, conn)
		if err != nil {
			fmt.Fprintln(os.Stderr, "connection error:", err)
		}
		if shutdownRequested {
			fmt.Fprintln(os.Stderr, "server shutdown requested")
			break
		}
	}

	return nil
}

func validateToken(token string) error {
	if token == "" {
		return errors.New("token must not be empty")
	}
	if len(token) > maxTokenLen {
		return errors.New("token too long")
	}
	return nil
}

func performHandshakeServer(conn net.Conn, expectedToken string) error {
	lenBuf := []byte{0, 0}
	if err := readExactWithTimeout(conn, lenBuf, readTimeout); err != nil {
		return err
	}
	tokenLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if tokenLen == 0 || tokenLen > maxTokenLen {
		_ = writeAllWithTimeout(conn, []byte{0}, writeTimeout)
		return errors.New("invalid token length")
	}

	tokenBuf := make([]byte, tokenLen)
	if err := readExactWithTimeout(conn, tokenBuf, readTimeout); err != nil {
		return err
	}

	match := string(tokenBuf) == expectedToken
	resp := byte(0)
	if match {
		resp = 1
	}
	_ = writeAllWithTimeout(conn, []byte{resp}, writeTimeout)
	if !match {
		return errors.New("handshake token mismatch")
	}
	return nil
}

type forwardResult struct {
	direction string
	err       error
}

func runSession(ctx context.Context, conn net.Conn) (bool, error) {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan forwardResult, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		err := copyStdinToConn(sessionCtx, conn)
		results <- forwardResult{direction: "in", err: err}
	}()

	go func() {
		defer wg.Done()
		err := copyConnToStdout(sessionCtx, conn)
		results <- forwardResult{direction: "out", err: err}
	}()

	shutdownRequested := false
	var sessionErr error

	for {
		select {
		case <-ctx.Done():
			shutdownRequested = true
			sessionErr = nil
			goto shutdown
		case res := <-results:
			if res.direction == "in" {
				if res.err != nil {
					sessionErr = res.err
					goto shutdown
				}
				continue
			}
			if res.err != nil {
				sessionErr = res.err
			}
			goto shutdown
		}
	}

shutdown:
	cancel()
	closeWrite(conn)
	_ = conn.Close()
	_ = os.Stdin.Close()
	wg.Wait()

	return shutdownRequested, sessionErr
}

func copyStdinToConn(ctx context.Context, conn net.Conn) error {
	buf := make([]byte, bufferSize)
	for {
		if ctx.Err() != nil {
			return nil
		}

		n, err := os.Stdin.Read(buf)
		if n > 0 {
			if werr := writeAllWithTimeout(conn, buf[:n], writeTimeout); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				closeWrite(conn)
				return nil
			}
			return err
		}
	}
}

func copyConnToStdout(ctx context.Context, conn net.Conn) error {
	buf := make([]byte, bufferSize)
	for {
		if ctx.Err() != nil {
			return nil
		}

		n, err := readWithTimeout(conn, buf, readTimeout)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n == 0 {
			continue
		}
		if _, werr := os.Stdout.Write(buf[:n]); werr != nil {
			return werr
		}
	}
}

func readWithTimeout(conn net.Conn, buf []byte, timeout time.Duration) (int, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	n, err := conn.Read(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return 0, nil
		}
		return n, err
	}
	return n, nil
}

func readExactWithTimeout(conn net.Conn, buf []byte, timeout time.Duration) error {
	offset := 0
	for offset < len(buf) {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		n, err := conn.Read(buf[offset:])
		if n > 0 {
			offset += n
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func writeAllWithTimeout(conn net.Conn, buf []byte, timeout time.Duration) error {
	offset := 0
	for offset < len(buf) {
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		n, err := conn.Write(buf[offset:])
		if n > 0 {
			offset += n
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("write zero")
		}
	}
	return nil
}

func closeWrite(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
		return
	}
	_ = conn.Close()
}
