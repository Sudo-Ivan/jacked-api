package jacked

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

// TestServerCreation tests server creation with default and custom configs
func TestServerCreation(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		validate func(*testing.T, *Server)
	}{
		{
			name:   "Default Config",
			config: nil,
			validate: func(t *testing.T, s *Server) {
				if s.config == nil {
					t.Error("Expected non-nil config")
				}
				if s.config.MaxConns != defaultMaxConns {
					t.Errorf("Expected MaxConns %d, got %d", defaultMaxConns, s.config.MaxConns)
				}
			},
		},
		{
			name: "Custom Config",
			config: &Config{
				MaxConns:    2000,
				ReadTimeout: 30 * time.Second,
			},
			validate: func(t *testing.T, s *Server) {
				if s.config.MaxConns != 2000 {
					t.Errorf("Expected MaxConns 2000, got %d", s.config.MaxConns)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s *Server
			if tt.config == nil {
				s = New()
			} else {
				s = NewWithConfig(tt.config)
			}
			tt.validate(t, s)
		})
	}
}

// TestSecurityHeaders tests that security headers are properly set
func TestSecurityHeaders(t *testing.T) {
	app := New()
	app.GET("/test", func(c *Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)

	headers := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'self'",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
	}

	for key, expected := range headers {
		if got := w.Header().Get(key); got != expected {
			t.Errorf("Expected header %s: %s, got %s", key, expected, got)
		}
	}
}

// TestCORS tests CORS handling
func TestCORS(t *testing.T) {
	tests := []struct {
		name           string
		origin         string
		allowedOrigins []string
		shouldAllow    bool
	}{
		{
			name:           "Allowed Origin",
			origin:         "https://example.com",
			allowedOrigins: []string{"https://example.com"},
			shouldAllow:    true,
		},
		{
			name:           "Disallowed Origin",
			origin:         "https://malicious.com",
			allowedOrigins: []string{"https://example.com"},
			shouldAllow:    false,
		},
		{
			name:           "Wildcard Origin",
			origin:         "https://any.com",
			allowedOrigins: []string{"*"},
			shouldAllow:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.AllowedOrigins = tt.allowedOrigins
			app := NewWithConfig(config)

			app.GET("/test", func(c *Context) error {
				return c.JSON(200, map[string]string{"status": "ok"})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Origin", tt.origin)
			w := httptest.NewRecorder()
			app.ServeHTTP(w, req)

			allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
			if tt.shouldAllow {
				if allowOrigin != tt.origin {
					t.Errorf("Expected Access-Control-Allow-Origin: %s, got %s", tt.origin, allowOrigin)
				}
			} else {
				if allowOrigin != "" {
					t.Errorf("Expected no Access-Control-Allow-Origin, got %s", allowOrigin)
				}
			}
		})
	}
}

// TestRequestSizeLimit tests request size limiting
func TestRequestSizeLimit(t *testing.T) {
	config := DefaultConfig()
	config.MaxRequestSize = 10 // Set small limit for testing
	app := NewWithConfig(config)

	app.POST("/test", func(c *Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	// Test oversized request
	largeBody := strings.Repeat("a", 20)
	req := httptest.NewRequest("POST", "/test", strings.NewReader(largeBody))
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)

	if w.Code != statusRequestEntityTooLarge {
		t.Errorf("Expected status %d, got %d", statusRequestEntityTooLarge, w.Code)
	}

	// Test acceptable request
	smallBody := strings.Repeat("a", 5)
	req = httptest.NewRequest("POST", "/test", strings.NewReader(smallBody))
	w = httptest.NewRecorder()
	app.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

// TestMiddlewareChain tests middleware execution order and error handling
func TestMiddlewareChain(t *testing.T) {
	app := New()
	executionOrder := []string{}

	app.Use(func(c *Context) error {
		executionOrder = append(executionOrder, "middleware1")
		return c.Next()
	})

	app.Use(func(c *Context) error {
		executionOrder = append(executionOrder, "middleware2")
		return c.Next()
	})

	app.GET("/test", func(c *Context) error {
		executionOrder = append(executionOrder, "handler")
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)

	expectedOrder := []string{"middleware1", "middleware2", "handler"}
	if len(executionOrder) != len(expectedOrder) {
		t.Errorf("Expected %d executions, got %d", len(expectedOrder), len(executionOrder))
	}
	for i, expected := range expectedOrder {
		if executionOrder[i] != expected {
			t.Errorf("Expected %s at position %d, got %s", expected, i, executionOrder[i])
		}
	}
}

// TestErrorHandling tests error handling in handlers and middleware
func TestErrorHandling(t *testing.T) {
	app := New()
	app.GET("/error", func(c *Context) error {
		return c.JSON(500, map[string]string{"error": "test error"})
	})

	req := httptest.NewRequest("GET", "/error", nil)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Errorf("Expected status 500, got %d", w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response["error"] != "test error" {
		t.Errorf("Expected error message 'test error', got %s", response["error"])
	}
}

// TestConcurrentRequests tests handling of concurrent requests
func TestConcurrentRequests(t *testing.T) {
	app := New()
	app.GET("/test", func(c *Context) error {
		time.Sleep(10 * time.Millisecond) // Simulate work
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	concurrent := 10
	done := make(chan bool)

	for i := 0; i < concurrent; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			app.ServeHTTP(w, req)
			if w.Code != 200 {
				t.Errorf("Expected status 200, got %d", w.Code)
			}
			done <- true
		}()
	}

	for i := 0; i < concurrent; i++ {
		<-done
	}
}

// TestGracefulShutdown tests server shutdown behavior
func TestGracefulShutdown(t *testing.T) {
	app := New()
	app.GET("/test", func(c *Context) error {
		time.Sleep(100 * time.Millisecond) // Simulate long-running request
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	server := httptest.NewServer(app)
	defer server.Close()

	// Start a request
	req, _ := http.NewRequest("GET", server.URL+"/test", nil)
	go http.DefaultClient.Do(req)

	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if err := app.Shutdown(ctx); err != nil {
		t.Errorf("Expected no error during shutdown, got %v", err)
	}
}

// TestJSONResponse tests JSON response handling
func TestJSONResponse(t *testing.T) {
	app := New()
	app.GET("/test", func(c *Context) error {
		return c.JSON(200, map[string]interface{}{
			"string": "value",
			"number": 42,
			"bool":   true,
			"array":  []string{"a", "b", "c"},
		})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", w.Header().Get("Content-Type"))
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}

	// Test string value
	if str, ok := response["string"].(string); !ok || str != "value" {
		t.Errorf("Expected string 'value', got %v", response["string"])
	}

	// Test number value
	if num, ok := response["number"].(float64); !ok || num != 42 {
		t.Errorf("Expected number 42, got %v", response["number"])
	}

	// Test boolean value
	if b, ok := response["bool"].(bool); !ok || !b {
		t.Errorf("Expected boolean true, got %v", response["bool"])
	}

	// Test array value
	arr, ok := response["array"].([]interface{})
	if !ok {
		t.Errorf("Expected array, got %v", response["array"])
	}
	expectedArr := []string{"a", "b", "c"}
	if len(arr) != len(expectedArr) {
		t.Errorf("Expected array length %d, got %d", len(expectedArr), len(arr))
	}
	for i, v := range arr {
		if str, ok := v.(string); !ok || str != expectedArr[i] {
			t.Errorf("Expected array element %s at index %d, got %v", expectedArr[i], i, v)
		}
	}
}

// TestMaliciousHeaders tests handling of malicious headers
func TestMaliciousHeaders(t *testing.T) {
	app := New()
	app.GET("/test", func(c *Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	tests := []struct {
		name   string
		header string
		value  string
	}{
		{
			name:   "XSS Attack Header",
			header: "X-XSS-Protection",
			value:  "0",
		},
		{
			name:   "Content-Type Override",
			header: "Content-Type",
			value:  "text/html",
		},
		{
			name:   "Malicious Origin",
			header: "Origin",
			value:  "javascript:alert(1)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set(tt.header, tt.value)
			w := httptest.NewRecorder()
			app.ServeHTTP(w, req)

			// Verify security headers are still set correctly
			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Error("Security header X-Content-Type-Options was not set correctly")
			}
			if w.Header().Get("Content-Type") != "application/json" {
				t.Error("Content-Type was not set correctly")
			}
		})
	}
}

// TestRateLimitConfiguration tests different rate limit configurations
func TestRateLimitConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		rateLimit  int
		burstLimit int
		requests   int
		expected   int
	}{
		{
			name:       "NoRateLimit",
			rateLimit:  0,
			burstLimit: 0,
			requests:   10,
			expected:   200,
		},
		{
			name:       "NegativeRateLimit",
			rateLimit:  -1,
			burstLimit: -1,
			requests:   10,
			expected:   200,
		},
		{
			name:       "StrictRateLimit",
			rateLimit:  1,
			burstLimit: 1,
			requests:   2,
			expected:   statusTooManyRequests,
		},
		{
			name:       "GenerousBurst",
			rateLimit:  1,
			burstLimit: 5,
			requests:   5,
			expected:   200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.RateLimit = tt.rateLimit
			config.BurstLimit = tt.burstLimit
			app := NewWithConfig(config)

			app.GET("/test", func(c *Context) error {
				return c.JSON(200, map[string]string{"status": "ok"})
			})

			var lastStatus int
			for i := 0; i < tt.requests; i++ {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "127.0.0.1:12345"
				w := httptest.NewRecorder()
				app.ServeHTTP(w, req)
				lastStatus = w.Code
			}

			if lastStatus != tt.expected {
				t.Errorf("Expected status %d, got %d", tt.expected, lastStatus)
			}
		})
	}
}

// TestRateLimitCleanup tests the cleanup of rate limit data
func TestRateLimitCleanup(t *testing.T) {
	config := DefaultConfig()
	config.RateLimit = 1 // Enable rate limiting
	config.CleanupWindow = 100 * time.Millisecond
	app := NewWithConfig(config)

	app.GET("/test", func(c *Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	// Make some requests
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)

	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)

	// Make another request - should be allowed as the previous data should be cleaned up
	w = httptest.NewRecorder()
	app.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200 after cleanup, got %d", w.Code)
	}
}

// TestRateLimitEdgeCases tests edge cases in rate limiting
func TestRateLimitEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		config         *Config
		expectedStatus int
	}{
		{
			name: "ZeroCleanupWindow",
			config: func() *Config {
				c := DefaultConfig()
				c.RateLimit = 1
				c.CleanupWindow = 0
				return c
			}(),
			expectedStatus: 200, // Should use default cleanup window
		},
		{
			name: "NegativeCleanupWindow",
			config: func() *Config {
				c := DefaultConfig()
				c.RateLimit = 1
				c.CleanupWindow = -1
				return c
			}(),
			expectedStatus: 200, // Should use default cleanup window
		},
		{
			name: "ZeroRateWindow",
			config: func() *Config {
				c := DefaultConfig()
				c.RateLimit = 1
				c.RateWindow = 0
				return c
			}(),
			expectedStatus: 200, // Should use default rate window
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewWithConfig(tt.config)

			app.GET("/test", func(c *Context) error {
				return c.JSON(200, map[string]string{"status": "ok"})
			})

			// Make two requests in quick succession
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "127.0.0.1:12345"

			// First request should succeed
			w := httptest.NewRecorder()
			app.ServeHTTP(w, req)
			if w.Code != 200 {
				t.Errorf("First request: Expected status 200, got %d", w.Code)
			}

			// Second request should be rate limited
			w = httptest.NewRecorder()
			app.ServeHTTP(w, req)
			if w.Code != tt.expectedStatus {
				t.Errorf("Second request: Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// TestInvalidJSON tests handling of invalid JSON requests
func TestInvalidJSON(t *testing.T) {
	app := New()
	app.POST("/test", func(c *Context) error {
		var data map[string]interface{}
		if err := json.NewDecoder(c.Request.Body).Decode(&data); err != nil {
			return c.JSON(400, map[string]string{"error": "invalid json"})
		}
		return c.JSON(200, data)
	})

	tests := []struct {
		name     string
		body     string
		expected int
	}{
		{
			name:     "Valid JSON",
			body:     `{"key": "value"}`,
			expected: 200,
		},
		{
			name:     "Invalid JSON",
			body:     `{"key": "value"`,
			expected: 400,
		},
		{
			name:     "Malformed JSON",
			body:     `{"key": "value",}`,
			expected: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			app.ServeHTTP(w, req)

			if w.Code != tt.expected {
				t.Errorf("Expected status %d, got %d", tt.expected, w.Code)
			}
		})
	}
}

// TestAbortMiddleware tests middleware chain abortion
func TestAbortMiddleware(t *testing.T) {
	app := New()
	executionOrder := []string{}

	app.Use(func(c *Context) error {
		executionOrder = append(executionOrder, "middleware1")
		c.Abort()
		return nil
	})

	app.Use(func(c *Context) error {
		executionOrder = append(executionOrder, "middleware2")
		return c.Next()
	})

	app.GET("/test", func(c *Context) error {
		executionOrder = append(executionOrder, "handler")
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)

	if len(executionOrder) != 1 {
		t.Errorf("Expected 1 execution, got %d", len(executionOrder))
	}
	if executionOrder[0] != "middleware1" {
		t.Errorf("Expected middleware1, got %s", executionOrder[0])
	}
}

// BenchmarkSimpleRequest measures the performance of a simple GET request
func BenchmarkSimpleRequest(b *testing.B) {
	app := New()
	app.GET("/test", func(c *Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		app.ServeHTTP(w, req)
	}
}

// BenchmarkConcurrentRequests measures performance under concurrent load
func BenchmarkConcurrentRequests(b *testing.B) {
	app := New()
	app.GET("/test", func(c *Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		for pb.Next() {
			app.ServeHTTP(w, req)
		}
	})
}

// BenchmarkJSONResponse measures performance of JSON responses with different payload sizes
func BenchmarkJSONResponse(b *testing.B) {
	tests := []struct {
		name    string
		payload interface{}
	}{
		{
			name:    "Small",
			payload: map[string]string{"status": "ok"},
		},
		{
			name: "Medium",
			payload: map[string]interface{}{
				"status": "ok",
				"data":   map[string]string{"key1": "value1", "key2": "value2"},
				"array":  []int{1, 2, 3, 4, 5},
			},
		},
		{
			name: "Large",
			payload: map[string]interface{}{
				"status": "ok",
				"data":   map[string]string{"key1": "value1", "key2": "value2"},
				"array":  make([]int, 1000),
				"nested": map[string]interface{}{
					"level1": map[string]interface{}{
						"level2": map[string]interface{}{
							"level3": "deep value",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			app := New()
			app.GET("/test", func(c *Context) error {
				return c.JSON(200, tt.payload)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				app.ServeHTTP(w, req)
			}
		})
	}
}

// BenchmarkMiddlewareChain measures performance with different numbers of middleware
func BenchmarkMiddlewareChain(b *testing.B) {
	tests := []struct {
		name            string
		middlewareCount int
	}{
		{"NoMiddleware", 0},
		{"OneMiddleware", 1},
		{"FiveMiddleware", 5},
		{"TenMiddleware", 10},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			app := New()

			// Add middleware
			for i := 0; i < tt.middlewareCount; i++ {
				app.Use(func(c *Context) error {
					return c.Next()
				})
			}

			app.GET("/test", func(c *Context) error {
				return c.JSON(200, map[string]string{"status": "ok"})
			})

			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				app.ServeHTTP(w, req)
			}
		})
	}
}

// BenchmarkRequestParsing measures performance of request parsing with different body sizes
func BenchmarkRequestParsing(b *testing.B) {
	tests := []struct {
		name     string
		bodySize int
	}{
		{"SmallBody", 100},
		{"MediumBody", 1000},
		{"LargeBody", 10000},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			app := New()
			app.POST("/test", func(c *Context) error {
				var data map[string]interface{}
				if err := json.NewDecoder(c.Request.Body).Decode(&data); err != nil {
					return c.JSON(400, map[string]string{"error": "invalid json"})
				}
				return c.JSON(200, data)
			})

			// Create test data
			data := make(map[string]string)
			for i := 0; i < tt.bodySize; i++ {
				data[fmt.Sprintf("key%d", i)] = fmt.Sprintf("value%d", i)
			}
			body, _ := json.Marshal(data)

			req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				req.Body = io.NopCloser(bytes.NewReader(body)) // Reset body for each iteration
				app.ServeHTTP(w, req)
			}
		})
	}
}

// BenchmarkWithMiddlewareWork measures performance with middleware that performs work
func BenchmarkWithMiddlewareWork(b *testing.B) {
	app := New()

	// Middleware simulating some work (e.g., checking a header)
	app.Use(func(c *Context) error {
		if c.Request.Header.Get("X-Auth-Token") == "" {
			// Simulate unauthorized path, though for benchmark it continues
		}
		time.Sleep(1 * time.Millisecond) // Simulate processing time
		return c.Next()
	})

	app.GET("/test", func(c *Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Auth-Token", "valid-token") // Add header for middleware
	w := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		app.ServeHTTP(w, req)
	}
}

// BenchmarkMixedRequests measures performance with concurrent GET and POST requests
func BenchmarkMixedRequests(b *testing.B) {
	app := New()

	app.GET("/get", func(c *Context) error {
		return c.JSON(200, map[string]string{"method": "GET"})
	})

	app.POST("/post", func(c *Context) error {
		var data map[string]interface{}
		// Use StreamJSON for potentially large bodies
		if err := c.StreamJSON(c.Request.Body, &data); err != nil {
			return c.JSON(400, map[string]string{"error": "invalid json"})
		}
		return c.JSON(200, map[string]string{"method": "POST", "received": "ok"})
	})

	postBody := `{"key": "value"}`
	postBodyBytes := []byte(postBody)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Alternate between GET and POST (simple way to mix)
			// In a real scenario, the mix ratio might be different
			if time.Now().UnixNano()%2 == 0 {
				req := httptest.NewRequest("GET", "/get", nil)
				w := httptest.NewRecorder()
				app.ServeHTTP(w, req)
			} else {
				req := httptest.NewRequest("POST", "/post", bytes.NewReader(postBodyBytes))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				app.ServeHTTP(w, req)
			}
		}
	})
}

// TestBufferPool tests the buffer pool functionality
func TestBufferPool(t *testing.T) {
	pool := newBufferPool(10)

	// Test getting and putting buffers
	buf1 := pool.get()
	buf2 := pool.get()

	if buf1 == buf2 {
		t.Error("Expected different buffers from pool")
	}

	// Write to buffers
	buf1.WriteString("test1")
	buf2.WriteString("test2")

	// Put buffers back
	pool.put(buf1)
	pool.put(buf2)

	// Get buffers again
	buf3 := pool.get()
	buf4 := pool.get()

	// Verify buffers were reset
	if buf3.Len() != 0 || buf4.Len() != 0 {
		t.Error("Expected buffers to be reset")
	}
}

// TestStreamingJSON tests streaming JSON parsing
func TestStreamingJSON(t *testing.T) {
	app := New()

	// Test with large JSON payload
	largeData := make(map[string]interface{})
	for i := 0; i < 1000; i++ {
		largeData[fmt.Sprintf("key%d", i)] = fmt.Sprintf("value%d", i)
	}

	app.POST("/test", func(c *Context) error {
		var data map[string]interface{}
		if err := c.StreamJSON(c.Request.Body, &data); err != nil {
			return c.JSON(400, map[string]string{"error": "invalid json"})
		}
		return c.JSON(200, data)
	})

	// Create test data
	body, _ := json.Marshal(largeData)

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	app.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}

	if len(response) != len(largeData) {
		t.Errorf("Expected %d items, got %d", len(largeData), len(response))
	}
}

// BenchmarkBufferPool measures buffer pool performance
func BenchmarkBufferPool(b *testing.B) {
	pool := newBufferPool(1000)

	b.Run("GetPut", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			buf := pool.get()
			buf.WriteString("test")
			pool.put(buf)
		}
	})

	b.Run("Concurrent", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				buf := pool.get()
				buf.WriteString("test")
				pool.put(buf)
			}
		})
	})
}

// BenchmarkStreamingJSON measures streaming JSON parsing performance
func BenchmarkStreamingJSON(b *testing.B) {
	app := New()

	// Create test data
	data := make(map[string]interface{})
	for i := 0; i < 1000; i++ {
		data[fmt.Sprintf("key%d", i)] = fmt.Sprintf("value%d", i)
	}
	body, _ := json.Marshal(data)

	app.POST("/test", func(c *Context) error {
		var result map[string]interface{}
		if err := c.StreamJSON(c.Request.Body, &result); err != nil {
			return c.JSON(400, map[string]string{"error": "invalid json"})
		}
		return c.JSON(200, result)
	})

	req := httptest.NewRequest("POST", "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Body = io.NopCloser(bytes.NewReader(body))
		app.ServeHTTP(w, req)
	}
}

// BenchmarkCORSOptions measures the performance of handling CORS preflight requests
func BenchmarkCORSOptions(b *testing.B) {
	config := DefaultConfig()
	config.AllowedOrigins = []string{"http://localhost:3000"} // Specific origin
	app := NewWithConfig(config)

	// Register a dummy route for the path
	app.POST("/test", func(c *Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")
	// app.ServeHTTP(w, req) // REMOVE THIS LINE 893

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Need a new recorder for each run as headers are set
		recorder := httptest.NewRecorder()
		app.ServeHTTP(recorder, req)
		// Ensure we get StatusNoContent (204) for successful preflight
		if recorder.Code != http.StatusNoContent {
			b.Fatalf("Expected status %d, got %d", http.StatusNoContent, recorder.Code)
		}
	}
}

// BenchmarkRoutingLarge measures routing performance with many registered routes
func BenchmarkRoutingLarge(b *testing.B) {
	app := New()
	numRoutes := 1000

	// Register many routes
	for i := 0; i < numRoutes; i++ {
		path := fmt.Sprintf("/route/%d", i)
		app.GET(path, func(c *Context) error {
			return c.JSON(200, map[string]int{"index": i}) // Capture i correctly
		})
	}

	// Target the middle route
	targetPath := fmt.Sprintf("/route/%d", numRoutes/2)
	req := httptest.NewRequest("GET", targetPath, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Need a new recorder each time to check the status code correctly
		w := httptest.NewRecorder()
		app.ServeHTTP(w, req)
		// Optional: Check status code if needed, but focus is routing lookup
		if w.Code != http.StatusOK {
			b.Fatalf("Expected status %d, got %d for path %s", http.StatusOK, w.Code, targetPath)
		}
		// Recorder automatically reset by creating a new one
		// w = httptest.NewRecorder()
	}
}

// BenchmarkHandlerError measures performance when a handler returns an error
func BenchmarkHandlerError(b *testing.B) {
	app := New()
	app.GET("/error", func(c *Context) error {
		// Simulate an error occurring in the handler
		return fmt.Errorf("simulated handler error")
	})

	req := httptest.NewRequest("GET", "/error", nil)
	// w := httptest.NewRecorder() // Remove this unused variable

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Need a new recorder each time because ServeHTTP writes the error response
		recorder := httptest.NewRecorder() // Ensure this line is present
		app.ServeHTTP(recorder, req)
		// Ensure we get the expected internal server error status
		if recorder.Code != http.StatusInternalServerError {
			b.Fatalf("Expected status %d, got %d", http.StatusInternalServerError, recorder.Code)
		}
	}
}

// TestPathParameters tests routing with path parameters (using httprouter now)
func TestPathParameters(t *testing.T) {
	app := New()

	// Handler to check parameters
	paramChecker := func(expectedParams map[string]string) HandlerFunc {
		return func(c *Context) error {
			// Check params using the new c.Param() method
			actualParams := make(map[string]string)
			for _, p := range c.Params { // Iterate httprouter.Params
				actualParams[p.Key] = p.Value
			}

			if len(actualParams) != len(expectedParams) {
				t.Errorf("Path: %s - Expected %d params, got %d", c.Request.URL.Path, len(expectedParams), len(actualParams))
				return c.JSON(500, map[string]string{"error": "param count mismatch"})
			}
			for key, expectedValue := range expectedParams {
				// Use c.Param(key) for checking individual params
				if actualValue := c.Param(key); actualValue != expectedValue {
					t.Errorf("Path: %s - Expected param '%s' to be '%s', got '%s'", c.Request.URL.Path, key, expectedValue, actualValue)
					return c.JSON(500, map[string]string{"error": "param value mismatch"})
				}
			}
			return c.JSON(200, actualParams) // Return actual extracted params
		}
	}

	// Register routes with parameters using httprouter syntax
	app.GET("/users/:userId", paramChecker(map[string]string{"userId": "123"}))
	app.GET("/users/:userId/posts/:postId", paramChecker(map[string]string{"userId": "abc", "postId": "456"}))
	app.POST("/orders/:orderId", paramChecker(map[string]string{"orderId": "xyz"}))
	app.GET("/files/:filepath", paramChecker(map[string]string{"filepath": "a.txt"}))
	// httprouter has explicit wildcard support: /files/*filepath
	// Let's add a separate test for that if needed, keep this for single segment param
	app.GET("/exact", paramChecker(map[string]string{}))

	tests := []struct {
		method         string
		path           string
		expectedStatus int
		expectedParams map[string]string // Used for assertion inside paramChecker now
	}{
		{"GET", "/users/123", http.StatusOK, map[string]string{"userId": "123"}},
		{"GET", "/users/abc/posts/456", http.StatusOK, map[string]string{"userId": "abc", "postId": "456"}},
		{"POST", "/orders/xyz", http.StatusOK, map[string]string{"orderId": "xyz"}},
		{"GET", "/files/a.txt", http.StatusOK, map[string]string{"filepath": "a.txt"}},
		{"GET", "/exact", http.StatusOK, map[string]string{}},
		{"GET", "/users", http.StatusNotFound, nil},              // Should be 404 by httprouter
		{"GET", "/users/123/posts", http.StatusNotFound, nil},    // Should be 404 by httprouter
		{"GET", "/users/123/", http.StatusNotFound, nil},         // httprouter default is redirect (301), configure for strict? Updated expectation to 404
		{"POST", "/users/123", http.StatusMethodNotAllowed, nil}, // Should be 405 by httprouter
	}

	for _, tt := range tests {
		t.Run(tt.method+"_"+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			app.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Path: %s - Expected status %d, got %d", tt.path, tt.expectedStatus, w.Code)
			}

			// No need to decode body for params check, it's done in the handler now.
		})
	}
}

// BenchmarkParametricRouting measures performance of routing with path parameters (using httprouter)
func BenchmarkParametricRouting(b *testing.B) {
	app := New()
	numRoutes := 100 // Number of parametric routes to register

	// Handler used in benchmark
	benchHandler := func(c *Context) error {
		_ = c.Param("userId") // Access params to ensure router extracts them
		_ = c.Param("dataId")
		return c.JSON(http.StatusOK, nil) // Minimal response
	}

	// Register a mix of parametric routes
	for i := 0; i < numRoutes; i++ {
		// Single parameter
		pathSingle := fmt.Sprintf("/items/%d/:itemId", i)
		app.GET(pathSingle, benchHandler)

		// Multiple parameters
		pathMulti := fmt.Sprintf("/users/%d/:userId/data/:dataId", i)
		app.GET(pathMulti, benchHandler)
	}

	// Target a route somewhere in the middle for the benchmark
	targetPath := fmt.Sprintf("/users/%d/benchmark_user/data/benchmark_data_id", numRoutes/2)
	req := httptest.NewRequest("GET", targetPath, nil)

	b.ResetTimer()
	// Using RunParallel to simulate concurrent routing lookups
	b.RunParallel(func(pb *testing.PB) {
		w := httptest.NewRecorder() // Create recorder inside parallel loop
		for pb.Next() {
			app.ServeHTTP(w, req) // httprouter handles the request
			// Reset recorder state for next iteration if necessary (usually handled by httptest)
			// w.Body.Reset()
			// w.Result().StatusCode = 0
			// Optional status check removed for pure routing benchmark speed
		}
	})
}

// TestPathTraversal tests protection against path traversal attacks
func TestPathTraversal(t *testing.T) {
	app := New()
	// Use *filepath to capture multiple segments for traversal testing
	app.GET("/files/*filepath", func(c *Context) error {
		// You might want to add logging here to see the captured filepath
		// t.Logf("Captured filepath: %s", c.Param("filepath"))
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		skipTest       bool
	}{
		{"ValidPath", "/files/a.txt", 200, false},                               // Should now be 200
		{"ValidPathWithSlash", "/files/subdir/file.txt", 200, false},            // Should now be 200
		{"TraversalAttempt", "/files/../../../etc/passwd", 400, false},          // Should be caught by handler -> 400
		{"TraversalWithEncoded", "/files/%2e%2e/%2e%2e/etc/passwd", 400, false}, // Should be caught by handler -> 400
		{"AbsolutePath", "/files//etc/passwd", 400, false},                      // Should be caught by handler -> 400
		{"WindowsPath", "/files/C:\\Windows\\System32", 400, false},             // Should be caught by handler -> 400
		{"ControlChars", "/files/\x00file.txt", 400, true},                      // Should be caught by handler -> 400 (Skipped due to URL parsing)
		{"MultipleDots", "/files/..../file.txt", 400, false},                    // Should be caught by handler -> 400
		{"MixedSlashes", "/files/subdir\\file.txt", 400, false},                 // Should be caught by handler -> 400
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipTest {
				t.Skip("Skipping test with invalid URL characters")
			}

			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			app.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d for path %s", tt.expectedStatus, w.Code, tt.path)
			}
		})
	}
}

// TestHeaderInjection tests protection against header injection attacks
func TestHeaderInjection(t *testing.T) {
	app := New()
	app.POST("/test", func(c *Context) error {
		// Simulate header processing
		contentType := c.Request.Header.Get("Content-Type")
		// Check for header injection by looking for newlines or multiple content types
		if strings.Contains(contentType, "\n") || strings.Contains(contentType, "\r") ||
			strings.Contains(contentType, ",") || strings.Contains(contentType, ";") {
			return c.JSON(400, map[string]string{"error": "invalid content type"})
		}
		if !strings.HasPrefix(contentType, "application/json") {
			return c.JSON(400, map[string]string{"error": "invalid content type"})
		}
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	tests := []struct {
		name           string
		contentType    string
		expectedStatus int
	}{
		{"ValidContentType", "application/json", 200},
		{"InvalidContentType", "text/html", 400},
		{"InjectedHeader", "application/json\r\nX-Injected: true", 400},
		{"MultipleContentType", "application/json, text/html", 400},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", nil)
			req.Header.Set("Content-Type", tt.contentType)
			w := httptest.NewRecorder()
			app.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d for content type %s", tt.expectedStatus, w.Code, tt.contentType)
			}
		})
	}
}

// TestRequestValidation tests various request validation scenarios
func TestRequestValidation(t *testing.T) {
	app := New()
	app.POST("/validate", func(c *Context) error {
		// Validate request method
		if c.Request.Method != "POST" {
			return c.JSON(405, map[string]string{"error": "method not allowed"})
		}

		// Validate content length
		if c.Request.ContentLength > 1024 {
			return c.JSON(413, map[string]string{"error": "request too large"})
		}

		// Validate content type
		if !strings.HasPrefix(c.Request.Header.Get("Content-Type"), "application/json") {
			return c.JSON(415, map[string]string{"error": "unsupported media type"})
		}

		return c.JSON(200, map[string]string{"status": "ok"})
	})

	tests := []struct {
		name           string
		method         string
		contentType    string
		contentLength  int64
		expectedStatus int
	}{
		{"ValidRequest", "POST", "application/json", 100, 200},
		{"InvalidMethod", "GET", "application/json", 100, 405},
		{"LargeRequest", "POST", "application/json", 2048, 413},
		{"InvalidContentType", "POST", "text/plain", 100, 415},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/validate", nil)
			req.Header.Set("Content-Type", tt.contentType)
			req.ContentLength = tt.contentLength
			w := httptest.NewRecorder()
			app.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d for test %s", tt.expectedStatus, w.Code, tt.name)
			}
		})
	}
}

// TestTrustedProxies tests the trusted proxies configuration
func TestTrustedProxies(t *testing.T) {
	config := DefaultConfig()
	config.TrustedProxies = []string{"10.0.0.1", "192.168.1.1"}
	app := NewWithConfig(config)

	app.GET("/test", func(c *Context) error {
		// Simulate proxy check
		clientIP := c.Request.RemoteAddr
		if !isTrustedProxy(clientIP, config.TrustedProxies) {
			return c.JSON(403, map[string]string{"error": "untrusted proxy"})
		}
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	tests := []struct {
		name           string
		remoteAddr     string
		expectedStatus int
	}{
		{"TrustedProxy1", "10.0.0.1:12345", 200},
		{"TrustedProxy2", "192.168.1.1:54321", 200},
		{"UntrustedProxy", "172.16.0.1:12345", 403},
		{"MalformedIP", "invalid-ip", 403},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			w := httptest.NewRecorder()
			app.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d for remote addr %s", tt.expectedStatus, w.Code, tt.remoteAddr)
			}
		})
	}
}

// Helper function for trusted proxy check
func isTrustedProxy(addr string, trustedProxies []string) bool {
	// Extract IP from addr (format: "IP:port")
	ip := strings.Split(addr, ":")[0]
	for _, trusted := range trustedProxies {
		if ip == trusted {
			return true
		}
	}
	return false
}
