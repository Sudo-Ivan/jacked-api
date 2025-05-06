package jacked

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	GoPath "path/filepath"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"
	"github.com/julienschmidt/httprouter"
)

const (
	// defaultReadTimeout is the default duration for reading the entire request, including the body.
	defaultReadTimeout = 15 * time.Second
	// defaultWriteTimeout is the default duration before timing out writes of the response.
	defaultWriteTimeout = 15 * time.Second
	// defaultIdleTimeout is the default amount of time a connection may be idle before closing.
	defaultIdleTimeout = 60 * time.Second
	// defaultHeaderTimeout is the amount of time allowed to read request headers.
	defaultHeaderTimeout = 5 * time.Second
	// defaultMaxAge is the default duration for caching CORS preflight requests.
	defaultMaxAge = 24 * time.Hour

	// defaultMaxConns is the default maximum number of concurrent connections.
	defaultMaxConns = 1000
	// defaultMaxHeaderSize is the default maximum size of request headers in bytes.
	defaultMaxHeaderSize = 1 << 20 // 1 MB
	// defaultMaxBodySize is the default maximum size of request body in bytes.
	defaultMaxBodySize = 1 << 20 // 1 MB

	// defaultRateLimit is the default number of requests allowed per RateWindow.
	defaultRateLimit = 100
	// defaultBurstLimit is the default maximum number of requests allowed in a burst.
	defaultBurstLimit = 200
	// defaultRateWindow is the default duration for rate limiting window.
	defaultRateWindow = time.Second
	// defaultCleanupWindow is the default duration for cleaning up expired rate limiters.
	defaultCleanupWindow = 5 * time.Minute

	// defaultCORSMaxAge is the default duration for caching CORS preflight requests.
	defaultCORSMaxAge = 12 * time.Hour
	// corsSeparator is the separator used to join CORS headers.
	corsSeparator = ", "

	statusNoContent             = http.StatusNoContent
	statusUnauthorized          = http.StatusUnauthorized
	statusInternalServerError   = http.StatusInternalServerError
	statusRequestEntityTooLarge = http.StatusRequestEntityTooLarge
	statusTooManyRequests       = http.StatusTooManyRequests

	initialHandlerIndex = -1
	firstStringIndex    = 0
	secondStringIndex   = 1

	poolSize = 1

	defaultBufferPoolSize = 1000
	defaultConnPoolSize   = 100

	initialBufferCapacity = 32 * 1024
	initialBufferSize     = 0
)

// Config holds the server configuration parameters.
type Config struct {
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	IdleTimeout           time.Duration
	ReadHeaderTimeout     time.Duration
	MaxConns              int
	TrustedProxies        []string
	AllowedOrigins        []string
	AllowedMethods        []string
	AllowedHeaders        []string
	ExposedHeaders        []string
	AllowCredentials      bool
	MaxAge                time.Duration
	MaxRequestSize        int64
	EnableCompression     bool
	EnableSecurityHeaders bool
	RateLimit             int
	BurstLimit            int
	RateWindow            time.Duration
	CleanupWindow         time.Duration
	bufferPool            *bufferPool
}

// DefaultConfig returns a Config struct with default values.
func DefaultConfig() *Config {
	return &Config{
		ReadTimeout:           defaultReadTimeout,
		WriteTimeout:          defaultWriteTimeout,
		IdleTimeout:           defaultIdleTimeout,
		ReadHeaderTimeout:     defaultHeaderTimeout,
		MaxConns:              defaultMaxConns,
		TrustedProxies:        []string{"127.0.0.1"},
		AllowedOrigins:        []string{"*"},
		AllowedMethods:        []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:        []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposedHeaders:        []string{"Content-Length"},
		AllowCredentials:      true,
		MaxAge:                defaultMaxAge,
		MaxRequestSize:        defaultMaxBodySize,
		EnableCompression:     true,
		EnableSecurityHeaders: true,
		RateLimit:             defaultRateLimit,
		BurstLimit:            defaultBurstLimit,
		RateWindow:            defaultRateWindow,
		CleanupWindow:         defaultCleanupWindow,
		bufferPool:            newBufferPool(defaultBufferPoolSize),
	}
}

// HandlerFunc defines the handler function signature for middleware and route handlers.
type HandlerFunc func(*Context) error

// Context represents the context of the current HTTP request.
type Context struct {
	Request       *http.Request
	Response      http.ResponseWriter
	Params        httprouter.Params
	ctx           context.Context
	index         int
	handlers      []HandlerFunc
	mu            sync.RWMutex
	config        *Config
	aborted       bool
	finalHandler  HandlerFunc
	statusWritten bool
}

// Param returns the value of the URL parameter for the given key.
func (c *Context) Param(key string) string {
	return c.Params.ByName(key)
}

// Server is the main server struct.
type Server struct {
	router     *httprouter.Router
	middleware []HandlerFunc
	mu         sync.RWMutex
	pool       chan struct{}
	config     *Config
	bufferPool *bufferPool
	limiter    *rateLimiter
}

// ServerArgs holds command line arguments for the server
type ServerArgs struct {
	Port  string
	Host  string
	Debug bool
}

// ParseArgs parses command line arguments
func ParseArgs() *ServerArgs {
	args := &ServerArgs{}

	// Long flags
	flag.StringVar(&args.Port, "port", "8080", "Port to listen on")
	flag.StringVar(&args.Host, "host", "", "Host to listen on")
	flag.BoolVar(&args.Debug, "debug", false, "Enable debug mode")

	// Short flags
	flag.StringVar(&args.Port, "p", "8080", "Port to listen on (shorthand)")
	flag.StringVar(&args.Host, "h", "", "Host to listen on (shorthand)")
	flag.BoolVar(&args.Debug, "d", false, "Enable debug mode (shorthand)")

	flag.Parse()
	return args
}

// New creates a new Server instance with the default configuration.
func New() *Server {
	return NewWithConfig(DefaultConfig())
}

// NewWithConfig creates a new Server instance with the given configuration.
func NewWithConfig(config *Config) *Server {
	router := httprouter.New()
	router.RedirectTrailingSlash = false

	s := &Server{
		router:     router,
		middleware: make([]HandlerFunc, 0),
		pool:       make(chan struct{}, config.MaxConns),
		config:     config,
		bufferPool: newBufferPool(defaultBufferPoolSize),
		limiter:    newRateLimiter(config),
	}

	router.GlobalOPTIONS = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Access-Control-Request-Method") != "" {
			origin := r.Header.Get("Origin")
			if origin == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			allowed := false
			for _, allowedOrigin := range s.config.AllowedOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			if s.config.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.Header().Set("Access-Control-Allow-Methods", join(s.config.AllowedMethods, corsSeparator))
			w.Header().Set("Access-Control-Allow-Headers", join(s.config.AllowedHeaders, corsSeparator))
			w.Header().Set("Access-Control-Max-Age", s.config.MaxAge.String())

			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})

	s.Use(s.corsMiddleware())
	s.Use(s.rateLimitMiddleware())

	router.NotFound = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	router.MethodNotAllowed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})

	return s
}

// Use adds middleware handlers to the server's middleware stack.
func (s *Server) Use(handlers ...HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.middleware = append(s.middleware, handlers...)
}

// Handle registers a new request handler with the given method and path.
func (s *Server) Handle(method, path string, handler HandlerFunc) {
	wrappedHandler := func(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
		select {
		case s.pool <- struct{}{}:
			defer func() { <-s.pool }()
		default:
			http.Error(w, "Too many connections", http.StatusServiceUnavailable)
			return
		}

		ctx := &Context{
			Request:      r,
			Response:     w,
			Params:       params,
			ctx:          r.Context(),
			index:        initialHandlerIndex,
			handlers:     s.middleware,
			config:       s.config,
			aborted:      false,
			finalHandler: handler,
		}

		if err := ctx.checkRequestSize(); err != nil {
			return
		}

		ctx.setSecurityHeaders()

		chainErr := ctx.Next()

		if chainErr != nil {
			ctx.mu.RLock()
			written := ctx.statusWritten
			ctx.mu.RUnlock()

			if !written {
				_ = ctx.JSON(statusInternalServerError, map[string]string{
					"error": "internal server error processing request",
				})
			}
		}
	}

	if strings.HasSuffix(path, "/*filepath") {
		originalHandler := wrappedHandler
		wrappedHandler = func(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
			filepathParam := params.ByName("filepath")

			if strings.ContainsAny(filepathParam, "\\\x00") {
				http.Error(w, "Invalid characters in filepath", http.StatusBadRequest)
				return
			}

			trimmedParam := strings.TrimPrefix(filepathParam, "/")

			if strings.Contains(trimmedParam, "..") || strings.HasPrefix(trimmedParam, "/") {
				http.Error(w, "Invalid filepath parameter (contains traversal or is absolute)", http.StatusBadRequest)
				return
			}

			cleanedTrimmedPath := GoPath.Clean(trimmedParam)
			if strings.HasPrefix(cleanedTrimmedPath, "..") {
				http.Error(w, "Invalid filepath parameter (cleaned path traversal)", http.StatusBadRequest)
				return
			}

			originalHandler(w, r, params)
		}
	}

	s.router.Handle(method, path, wrappedHandler)
}

// GET registers a new GET request handler with the given path.
func (s *Server) GET(path string, handler HandlerFunc) {
	s.Handle(http.MethodGet, path, handler)
}

// POST registers a new POST request handler with the given path.
func (s *Server) POST(path string, handler HandlerFunc) {
	s.Handle(http.MethodPost, path, handler)
}

// PUT registers a new PUT request handler with the given path.
func (s *Server) PUT(path string, handler HandlerFunc) {
	s.Handle(http.MethodPut, path, handler)
}

// DELETE registers a new DELETE request handler with the given path.
func (s *Server) DELETE(path string, handler HandlerFunc) {
	s.Handle(http.MethodDelete, path, handler)
}

// StreamJSON decodes JSON from the given io.Reader and stores it in the value pointed to by v.
func (c *Context) StreamJSON(r io.Reader, v interface{}) error {
	decoder := json.NewDecoder(r)
	decoder.UseNumber()
	return decoder.Decode(v)
}

// JSON sends a JSON response with the given status code and payload.
func (c *Context) JSON(status int, v interface{}) error {
	c.mu.Lock()
	if c.statusWritten {
		c.mu.Unlock()
		return nil
	}
	c.statusWritten = true
	c.mu.Unlock()

	if status == http.StatusNoContent {
		c.Response.WriteHeader(status)
		return nil
	}

	c.Response.Header().Set("Content-Type", "application/json")
	c.Response.WriteHeader(status)

	if v == nil {
		return nil
	}

	encoder := json.NewEncoder(c.Response)
	return encoder.Encode(v)
}

// String sends a string response with the given status code and message.
func (c *Context) String(status int, message string) error {
	c.mu.Lock()
	if c.statusWritten {
		c.mu.Unlock()
		return nil
	}
	c.statusWritten = true
	c.mu.Unlock()

	c.Response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	c.Response.WriteHeader(status)
	_, err := c.Response.Write([]byte(message))
	return err
}

// Next executes the next handler in the chain.
func (c *Context) Next() error {
	c.index++

	c.mu.RLock()
	if c.aborted || c.index > len(c.handlers) {
		c.mu.RUnlock()
		return nil
	}
	currentIndex := c.index
	c.mu.RUnlock()

	var handlerToCall HandlerFunc
	if currentIndex < len(c.handlers) {
		handlerToCall = c.handlers[currentIndex]
	} else if currentIndex == len(c.handlers) && c.finalHandler != nil {
		handlerToCall = c.finalHandler
	} else {
		return nil
	}

	return handlerToCall(c)
}

// Abort prevents further handlers from being executed.
func (c *Context) Abort() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.aborted {
		return
	}
	c.aborted = true
}

// setSecurityHeaders sets common security headers on the response.
func (c *Context) setSecurityHeaders() {
	if !c.config.EnableSecurityHeaders {
		return
	}

	headers := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":   "default-src 'self'",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
	}

	for key, value := range headers {
		c.Response.Header().Set(key, value)
	}
}

// isOriginAllowed checks if the given origin is allowed based on the server's configuration.
func (c *Context) isOriginAllowed(origin string) bool {
	if c.config == nil {
		return false
	}
	for _, allowedOrigin := range c.config.AllowedOrigins {
		if allowedOrigin == "*" || allowedOrigin == origin {
			return true
		}
	}
	return false
}

// setCORSHeaders sets the CORS headers on the response.
func (c *Context) setCORSHeaders(origin string) {
	c.Response.Header().Set("Access-Control-Allow-Origin", origin)
	if c.config.AllowCredentials {
		c.Response.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	c.Response.Header().Set("Access-Control-Allow-Methods", join(c.config.AllowedMethods, corsSeparator))
	c.Response.Header().Set("Access-Control-Allow-Headers", join(c.config.AllowedHeaders, corsSeparator))
	c.Response.Header().Set("Access-Control-Expose-Headers", join(c.config.ExposedHeaders, corsSeparator))
	c.Response.Header().Set("Access-Control-Max-Age", c.config.MaxAge.String())
}

// corsMiddleware is a middleware that handles Cross-Origin Resource Sharing (CORS).
func (s *Server) corsMiddleware() HandlerFunc {
	return func(c *Context) error {
		origin := c.Request.Header.Get("Origin")
		if origin == "" {
			return c.Next()
		}

		if !c.isOriginAllowed(origin) {
			return c.Next()
		}

		c.setCORSHeaders(origin)

		if c.Request.Method == "OPTIONS" {
			c.Abort()
			c.Response.WriteHeader(statusNoContent)
			return nil
		}

		return c.Next()
	}
}

// checkRequestSize checks if the request size exceeds the maximum allowed size.
func (c *Context) checkRequestSize() error {
	if c.Request.ContentLength > c.config.MaxRequestSize {
		_ = c.JSON(statusRequestEntityTooLarge, map[string]string{
			"error": "request too large",
		})
		c.Abort()
		return fmt.Errorf("request too large")
	}
	return nil
}

// ServeHTTP makes the server implement the http.Handler interface.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// ListenAndServe starts the server and listens for incoming connections on the specified address.
func (s *Server) ListenAndServe(addr string) error {
	args := ParseArgs()

	// Construct address from host and port
	var listenAddr string
	if args.Host != "" {
		listenAddr = fmt.Sprintf("%s:%s", args.Host, args.Port)
	} else {
		listenAddr = ":" + args.Port
	}

	if args.Debug {
		fmt.Printf("[DEBUG] Server configuration:\n")
		fmt.Printf("  Host: %s\n", args.Host)
		fmt.Printf("  Port: %s\n", args.Port)
		fmt.Printf("  Debug: %v\n", args.Debug)
		fmt.Printf("  Listen Address: %s\n", listenAddr)
	}

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           s,
		ReadTimeout:       s.config.ReadTimeout,
		WriteTimeout:      s.config.WriteTimeout,
		IdleTimeout:       s.config.IdleTimeout,
		ReadHeaderTimeout: s.config.ReadHeaderTimeout,
		MaxHeaderBytes:    defaultMaxHeaderSize,
	}
	return server.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	svr := &http.Server{
		Addr:              ":8080",
		Handler:           s,
		ReadTimeout:       s.config.ReadTimeout,
		WriteTimeout:      s.config.WriteTimeout,
		IdleTimeout:       s.config.IdleTimeout,
		ReadHeaderTimeout: s.config.ReadHeaderTimeout,
		MaxHeaderBytes:    defaultMaxHeaderSize,
	}

	if s.limiter != nil {
		s.limiter.stop()
	}

	return svr.Shutdown(ctx)
}

// join concatenates a slice of strings into a single string with the given separator.
func join(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}

	var builder strings.Builder
	builder.WriteString(strs[0])

	for _, s := range strs[1:] {
		builder.WriteString(sep)
		builder.WriteString(s)
	}
	return builder.String()
}

// bufferPool is a pool of bytes.Buffer objects.
type bufferPool struct {
	pool sync.Pool
}

// newBufferPool creates a new bufferPool.
func newBufferPool(_ int) *bufferPool {
	return &bufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return bytes.NewBuffer(make([]byte, initialBufferSize, initialBufferCapacity))
			},
		},
	}
}

// get retrieves a bytes.Buffer from the pool.
func (p *bufferPool) get() *bytes.Buffer {
	return p.pool.Get().(*bytes.Buffer)
}

// put returns a bytes.Buffer to the pool.
func (p *bufferPool) put(b *bytes.Buffer) {
	b.Reset()
	p.pool.Put(b)
}

// rateLimiter is a middleware that limits the rate of requests.
type rateLimiter struct {
	mu       sync.RWMutex
	clients  map[string]*tokenBucket
	config   *Config
	stopChan chan struct{}
}

// tokenBucket represents a token bucket for rate limiting.
type tokenBucket struct {
	tokens         float64
	lastRefill     time.Time
	rate           float64
	burst          float64
	refillInterval time.Duration
}

// newRateLimiter creates a new rate limiter.
func newRateLimiter(config *Config) *rateLimiter {
	if config.RateLimit < 0 {
		config.RateLimit = 0
	}
	if config.BurstLimit < 0 {
		config.BurstLimit = 0
	}
	if config.CleanupWindow <= 0 {
		config.CleanupWindow = defaultCleanupWindow
	}
	if config.RateWindow <= 0 {
		config.RateWindow = defaultRateWindow
	}

	rl := &rateLimiter{
		clients:  make(map[string]*tokenBucket),
		config:   config,
		stopChan: make(chan struct{}),
	}

	if config.RateLimit > 0 {
		go rl.cleanupLoop()
	}
	return rl
}

// cleanupLoop periodically cleans up the rate limiter.
func (rl *rateLimiter) cleanupLoop() {
	interval := rl.config.CleanupWindow
	if interval <= 0 {
		interval = defaultCleanupWindow
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopChan:
			return
		}
	}
}

// cleanup removes expired token buckets from the rate limiter.
func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, bucket := range rl.clients {
		if now.Sub(bucket.lastRefill) > rl.config.CleanupWindow {
			delete(rl.clients, ip)
		}
	}
}

// allow determines whether a request from the given IP address is allowed based on the rate limit.
func (rl *rateLimiter) allow(ip string) bool {
	if rl.config.RateLimit <= 0 {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.clients[ip]
	if !exists {
		bucket = &tokenBucket{
			tokens:         float64(rl.config.BurstLimit),
			lastRefill:     time.Now(),
			rate:           float64(rl.config.RateLimit),
			burst:          float64(rl.config.BurstLimit),
			refillInterval: rl.config.RateWindow,
		}
		rl.clients[ip] = bucket
	}

	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	bucket.lastRefill = now

	newTokens := elapsed.Seconds() * bucket.rate
	bucket.tokens = math.Min(bucket.burst, bucket.tokens+newTokens)

	if bucket.tokens >= 1 {
		bucket.tokens--
		return true
	}
	return false
}

// stop stops the rate limiter's cleanup loop.
func (rl *rateLimiter) stop() {
	close(rl.stopChan)
}

// rateLimitMiddleware is a middleware that limits the rate of requests based on IP address.
func (s *Server) rateLimitMiddleware() HandlerFunc {
	return func(c *Context) error {
		ip := c.Request.RemoteAddr
		if !s.limiter.allow(ip) {
			return c.JSON(statusTooManyRequests, map[string]string{
				"error": "rate limit exceeded",
			})
		}
		return c.Next()
	}
}

// AbortWithError sends a JSON error response with the given status code and error, then aborts the context.
// If the provided error is nil, it uses the default HTTP status text for the given code.
// Otherwise, it uses the provided error's message. Care should be taken not to expose sensitive internal errors.
func (c *Context) AbortWithError(statusCode int, err error) error {
	c.mu.Lock()
	if c.statusWritten {
		c.mu.Unlock()
		c.aborted = true
		return fmt.Errorf("headers already written, cannot send error response for: %v", err)
	}
	c.aborted = true
	c.mu.Unlock()

	clientErrorMessage := http.StatusText(statusCode)
	if err != nil {
		clientErrorMessage = err.Error()
	}

	return c.JSON(statusCode, map[string]string{"error": clientErrorMessage})
}

// NotFound is a helper function to respond with a 404 Not Found error.
// It calls AbortWithError internally. If message is empty, a default "Not Found" message is used.
func (c *Context) NotFound(message string) error {
	if message == "" {
		message = http.StatusText(http.StatusNotFound)
	}
	return c.AbortWithError(http.StatusNotFound, errors.New(message))
}

// BadRequest is a helper function to respond with a 400 Bad Request error.
// It calls AbortWithError internally. If message is empty, a default "Bad Request" message is used.
func (c *Context) BadRequest(message string) error {
	if message == "" {
		message = http.StatusText(http.StatusBadRequest)
	}
	return c.AbortWithError(http.StatusBadRequest, errors.New(message))
}

// InternalServerError is a helper function to respond with a 500 Internal Server Error.
// It calls AbortWithError internally. If the provided err is nil,
// a default "Internal Server Error" message is used.
// IMPORTANT: In a production environment, the actual `err` should be logged server-side.
// Avoid exposing detailed internal error messages to the client.
func (c *Context) InternalServerError(originalErr error) error {
	if originalErr != nil {
		return c.AbortWithError(http.StatusInternalServerError, originalErr)
	}
	defaultError := errors.New(http.StatusText(http.StatusInternalServerError))
	return c.AbortWithError(http.StatusInternalServerError, defaultError)
}
