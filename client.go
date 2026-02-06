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
	connectTimeout = 5 * time.Second
	readTimeout    = 30 * time.Second
	writeTimeout   = 10 * time.Second
	maxTokenLen    = 1024
	bufferSize     = 16 * 1024
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "client error:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 4 {
		return fmt.Errorf("usage: %s <server_ip> <server_port> <token>", os.Args[0])
	}

	serverIP := os.Args[1]
	serverPort := os.Args[2]
	token := os.Args[3]

	if err := validateToken(token); err != nil {
		return err
	}

	addr := net.JoinHostPort(serverIP, serverPort)
	conn, err := connectWithTimeout(addr, connectTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	if err := performHandshakeClient(conn, token); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	shutdownRequested, err := runSession(ctx, conn)
	if shutdownRequested {
		fmt.Fprintln(os.Stderr, "client shutdown requested")
	}
	return err
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

func connectWithTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	return dialer.Dial("tcp", addr)
}

func performHandshakeClient(conn net.Conn, token string) error {
	if len(token) > maxTokenLen {
		return errors.New("token too long")
	}

	lenBuf := []byte{byte(len(token) >> 8), byte(len(token))}
	if err := writeAllWithTimeout(conn, lenBuf, writeTimeout); err != nil {
		return err
	}
	if err := writeAllWithTimeout(conn, []byte(token), writeTimeout); err != nil {
		return err
	}

	resp := []byte{0}
	if err := readExactWithTimeout(conn, resp, readTimeout); err != nil {
		return err
	}
	if resp[0] != 1 {
		return errors.New("handshake rejected")
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
