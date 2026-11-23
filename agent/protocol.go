package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

// Envelope is a server-signed message: payload = base64(JSON), sig = base64(Ed25519(JSON)).
type Envelope struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

func (e Envelope) Verify(pub ed25519.PublicKey, out any) error {
	body, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return fmt.Errorf("payload encoding: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(e.Sig)
	if err != nil {
		return fmt.Errorf("signature encoding: %w", err)
	}
	if !ed25519.Verify(pub, body, sig) {
		return errors.New("signature does not match the pinned server key")
	}
	return json.Unmarshal(body, out)
}

type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body) }

type Client struct {
	base string
	http *http.Client
}

func NewClient(base string) *Client {
	u, err := url.Parse(base)
	if err == nil && u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		log.Printf("WARNING: server URL is not HTTPS; use HTTPS (ideally mutual TLS) in production")
	}
	return &Client{base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 20 * time.Second}}
}

func (c *Client) Post(path, token string, body any, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "KillSwitchAgent/"+agentVersion)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return &HTTPError{Status: resp.StatusCode, Body: strings.TrimSpace(string(data))}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func osName() string { return runtime.GOOS + "/" + runtime.GOARCH }
