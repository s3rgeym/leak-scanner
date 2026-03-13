package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetBaseDomainName(t *testing.T) {
	tests := []struct {
		host     string
		expected string
	}{
		{"www.google.com", "google"},
		{"google.com", "google"},
		{"sub.google.com", "sub"},
		{"localhost", "localhost"},
		{"127.0.0.1", "127"},
	}

	for _, tt := range tests {
		result := getBaseDomainName(tt.host)
		if result != tt.expected {
			t.Errorf("getBaseDomainName(%q) = %q; want %q", tt.host, result, tt.expected)
		}
	}
}

func TestLoadConfigDefault(t *testing.T) {
	config := loadConfig("")
	if len(config.Rules) != len(defaultConf.Rules) {
		t.Errorf("Expected %d default rules, got %d", len(defaultConf.Rules), len(config.Rules))
	}
}

func TestCheckURL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/leak.sql", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/sql")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("leak"))
	})
	mux.HandleFunc("/not-a-leak", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not a leak"))
	})
	mux.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := server.Client()
	errCount := new(int32)

	tests := []struct {
		name     string
		url      string
		rules    []string
		expected bool
	}{
		{"Found leak with correct content type", server.URL + "/leak.sql", []string{"application/sql"}, true},
		{"Found leak with any content type", server.URL + "/leak.sql", nil, true},
		{"Skip mismatching content type", server.URL + "/not-a-leak", []string{"application/sql"}, false},
		{"404 results in false", server.URL + "/404", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := Task{URL: tt.url, ContentTypes: tt.rules, BaseURL: server.URL}
			if got := checkURL(client, task, errCount); got != tt.expected {
				t.Errorf("checkURL() = %v, want %v", got, tt.expected)
			}
		})
	}
}
