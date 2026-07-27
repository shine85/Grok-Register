package cpa

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestManagementDeviceAuthStartAndPoll(t *testing.T) {
	var statusCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-Management-Key") != "secret" {
			t.Fatalf("missing CPA management auth headers")
		}
		switch r.URL.Path {
		case "/v0/management/xai-auth-url":
			if r.Method != http.MethodGet {
				t.Fatalf("start method=%s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "ok",
				"url":    "https://auth.x.ai/oauth2/device/verify?user_code=kkkk",
				"state":  "xai-test",
			})
		case "/v0/management/get-auth-status":
			if r.URL.Query().Get("state") != "xai-test" {
				t.Fatalf("state=%q", r.URL.Query().Get("state"))
			}
			statusCalls++
			if statusCalls == 1 {
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "wait"})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := NewManagementClient(ManagementConfig{BaseURL: srv.URL + "/v0/management", Key: "secret", Timeout: time.Second})
	auth, err := client.StartXAIAuth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if auth.State != "xai-test" || auth.UserCode != "kkkk" {
		t.Fatalf("auth=%+v", auth)
	}
	if err := client.WaitAuth(context.Background(), auth.State, 2*time.Millisecond, time.Second); err != nil {
		t.Fatal(err)
	}
	if statusCalls != 2 {
		t.Fatalf("status calls=%d", statusCalls)
	}
}

func TestManagementDeviceAuthRejectsCPAError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/xai-auth-url") {
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "blocked"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "expired"})
	}))
	defer srv.Close()
	client := NewManagementClient(ManagementConfig{BaseURL: srv.URL, Key: "k", Timeout: time.Second})
	if _, err := client.StartXAIAuth(context.Background()); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("expected start error, got %v", err)
	}
}

func TestManagementDeviceAuthRequiresUserCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"url":    "https://auth.x.ai/oauth2/device/verify",
			"state":  "xai-test",
		})
	}))
	defer srv.Close()
	client := NewManagementClient(ManagementConfig{BaseURL: srv.URL, Key: "k", Timeout: time.Second})
	if _, err := client.StartXAIAuth(context.Background()); err == nil || !strings.Contains(err.Error(), "user_code") {
		t.Fatalf("expected missing user_code error, got %v", err)
	}
}

func TestManagementDeviceAuthDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/get-auth-status") {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  "invalid_grant: Access denied",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	client := NewManagementClient(ManagementConfig{BaseURL: srv.URL, Key: "k", Timeout: time.Second})
	err := client.WaitAuth(context.Background(), "st", time.Millisecond, time.Second)
	if err == nil || !errors.Is(err, ErrDeviceAuthDenied) {
		t.Fatalf("expected ErrDeviceAuthDenied, got %v", err)
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("error=%v", err)
	}
}
