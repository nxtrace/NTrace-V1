package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeployLoginRejectsOversizedJSONTail(t *testing.T) {
	router := newDeployAuthTestRouter(deployAuth{Enabled: true, Token: "secret"})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/login", strings.NewReader(`{"token":"secret"}`+strings.Repeat(" ", 8192)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusRequestEntityTooLarge || len(resp.Result().Cookies()) != 0 {
		t.Fatalf("status=%d cookies=%d, want 413 without cookie", resp.Code, len(resp.Result().Cookies()))
	}
}

func loginBodyForLimitTest(t *testing.T, encoding string, size int) (string, string) {
	t.Helper()
	switch encoding {
	case "json":
		prefix := `{"token":"secret"}`
		return prefix + strings.Repeat(" ", size-len(prefix)), "application/json"
	case "form":
		prefix := "token=secret&pad="
		return prefix + strings.Repeat("a", size-len(prefix)), "application/x-www-form-urlencoded"
	default:
		build := func(pad int) (string, string) {
			var buf bytes.Buffer
			writer := multipart.NewWriter(&buf)
			if err := writer.SetBoundary("login-limit-test"); err != nil {
				t.Fatal(err)
			}
			if err := writer.WriteField("token", "secret"); err != nil {
				t.Fatal(err)
			}
			if err := writer.WriteField("pad", strings.Repeat("a", pad)); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			return buf.String(), writer.FormDataContentType()
		}
		base, _ := build(0)
		return build(size - len(base))
	}
}

func TestDeployLoginBodyLimits(t *testing.T) {
	router := newDeployAuthTestRouter(deployAuth{Enabled: true, Token: "secret"})
	for _, encoding := range []string{"json", "form", "multipart"} {
		for _, size := range []int{8191, 8192, 8193, 16384} {
			t.Run(fmt.Sprintf("%s/%d", encoding, size), func(t *testing.T) {
				body, contentType := loginBodyForLimitTest(t, encoding, size)
				req := httptest.NewRequestWithContext(context.Background(), "POST", "/auth/login", strings.NewReader(body))
				req.Header.Set("Content-Type", contentType)
				req.Header.Set("Accept", "application/json")
				resp := httptest.NewRecorder()
				router.ServeHTTP(resp, req)
				wantStatus, wantCookies := 200, 1
				if size > 8192 {
					wantStatus, wantCookies = 413, 0
				}
				if resp.Code != wantStatus || len(resp.Result().Cookies()) != wantCookies {
					t.Fatalf("status=%d cookies=%d, want %d/%d", resp.Code, len(resp.Result().Cookies()), wantStatus, wantCookies)
				}
			})
		}
	}
}

func TestDeployLoginChunkedBodyAndTrailingData(t *testing.T) {
	router := newDeployAuthTestRouter(deployAuth{Enabled: true, Token: "secret"})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength != -1 || len(r.TransferEncoding) != 1 || r.TransferEncoding[0] != "chunked" {
			t.Error("expected actual chunked transport")
		}
		router.ServeHTTP(w, r)
	}))
	defer server.Close()
	for _, encoding := range []string{"json", "form", "multipart"} {
		for _, tail := range []string{"", "x"} {
			body, contentType := loginBodyForLimitTest(t, encoding, 8192)
			req, err := http.NewRequestWithContext(context.Background(), "POST", server.URL+"/auth/login", struct{ io.Reader }{strings.NewReader(body + tail)})
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", contentType)
			req.Header.Set("Accept", "application/json")
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			wantStatus, wantCookies := 200, 1
			if tail != "" {
				wantStatus, wantCookies = 413, 0
			}
			if resp.StatusCode != wantStatus || len(resp.Cookies()) != wantCookies {
				t.Fatalf("%s tail=%q status=%d cookies=%d", encoding, tail, resp.StatusCode, len(resp.Cookies()))
			}
		}
	}
}

type loginReadError struct{}

func (loginReadError) Read([]byte) (int, error) { return 0, errors.New("broken body") }
func (loginReadError) Close() error             { return nil }

func TestDeployLoginReadErrorsAndEarlyReturns(t *testing.T) {
	for _, tc := range []struct {
		name   string
		auth   deployAuth
		status int
	}{
		{"read_error", deployAuth{Enabled: true, Token: "secret"}, 400},
		{"disabled", deployAuth{}, 200},
		{"missing_token", deployAuth{Enabled: true}, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), "POST", "/auth/login", nil)
			req.Body = loginReadError{}
			req.Header.Set("Accept", "application/json")
			resp := httptest.NewRecorder()
			newDeployAuthTestRouter(tc.auth).ServeHTTP(resp, req)
			if resp.Code != tc.status || len(resp.Result().Cookies()) != 0 {
				t.Fatalf("status=%d cookies=%d", resp.Code, len(resp.Result().Cookies()))
			}
		})
	}
}
