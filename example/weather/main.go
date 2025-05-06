package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sudo-Ivan/jacked-api/jacked"
)

// Logger wraps the standard logger with additional functionality
type Logger struct {
	*log.Logger
}

// NewLogger creates a new logger instance
func NewLogger() *Logger {
	return &Logger{
		Logger: log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds),
	}
}

// LogRequest logs incoming HTTP requests
func (l *Logger) LogRequest(method, path, remoteAddr string) {
	l.Printf("[REQUEST] %s %s from %s", method, path, remoteAddr)
}

// LogError logs error messages
func (l *Logger) LogError(err error, context string) {
	l.Printf("[ERROR] %s: %v", context, err)
}

// LogInfo logs informational messages
func (l *Logger) LogInfo(format string, v ...interface{}) {
	l.Printf("[INFO] "+format, v...)
}

// LogWeather logs weather data
func (l *Logger) LogWeather(city string, lat, lon float64, temp float64) {
	l.Printf("[WEATHER] City: %s, Lat: %.6f, Lon: %.6f, Temp: %.1f°C", city, lat, lon, temp)
}

// Metrics holds server performance metrics
type Metrics struct {
	TotalRequests   uint64
	FailedRequests  uint64
	AverageResponse float64
	LastMinuteHits  uint64
	StartTime       time.Time
	mu              sync.RWMutex
	lastMinuteHits  []time.Time
}

// NewMetrics creates a new metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		StartTime:      time.Now(),
		lastMinuteHits: make([]time.Time, 0),
	}
}

// RecordRequest records a request and its duration
func (m *Metrics) RecordRequest(duration time.Duration, failed bool) {
	atomic.AddUint64(&m.TotalRequests, 1)
	if failed {
		atomic.AddUint64(&m.FailedRequests, 1)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Update average response time
	m.AverageResponse = (m.AverageResponse*float64(m.TotalRequests-1) + duration.Seconds()) / float64(m.TotalRequests)

	// Record hit for last minute calculation
	now := time.Now()
	m.lastMinuteHits = append(m.lastMinuteHits, now)

	// Clean up old hits
	cutoff := now.Add(-time.Minute)
	for i, t := range m.lastMinuteHits {
		if t.After(cutoff) {
			m.lastMinuteHits = m.lastMinuteHits[i:]
			break
		}
	}
	m.LastMinuteHits = uint64(len(m.lastMinuteHits))
}

// GetUptime returns the server uptime
func (m *Metrics) GetUptime() time.Duration {
	return time.Since(m.StartTime)
}

// setSecurityHeaders sets appropriate security headers for the weather application
func setSecurityHeaders(w http.ResponseWriter) {
	// Set a more permissive CSP that allows necessary inline scripts
	csp := "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " + // Allow inline scripts and eval for weather app
		"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " + // Allow inline styles and Pico.css CDN
		"img-src 'self' data: https:; " + // Allow images from self, data URLs, and HTTPS sources
		"connect-src 'self' https://api.open-meteo.com https://geocoding-api.open-meteo.com; " + // Allow API connections
		"font-src 'self'; " + // Allow fonts from self
		"object-src 'none'; " + // Block plugins
		"base-uri 'self'; " + // Restrict base URI
		"form-action 'self'; " + // Restrict form submissions
		"frame-ancestors 'none'; " + // Prevent framing
		"block-all-mixed-content; " + // Block mixed content
		"upgrade-insecure-requests;" // Upgrade HTTP to HTTPS

	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
}

// validateURL ensures the URL is safe to use
func validateURL(rawURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow HTTPS
	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("only HTTPS URLs are allowed")
	}

	// Validate hostname
	allowedHosts := map[string]bool{
		"api.open-meteo.com":           true,
		"geocoding-api.open-meteo.com": true,
	}

	if !allowedHosts[parsedURL.Host] {
		return nil, fmt.Errorf("unauthorized host: %s", parsedURL.Host)
	}

	return parsedURL, nil
}

// createHTTPClient creates a secure HTTP client with timeouts
func createHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

var (
	logger     = NewLogger()
	httpClient = createHTTPClient()
	metrics    = NewMetrics()
)

type WeatherResponse struct {
	Temperature float64 `json:"temperature"`
	Humidity    float64 `json:"humidity"`
	WindSpeed   float64 `json:"wind_speed"`
	Description string  `json:"description"`
	City        string  `json:"city"`
	Timestamp   string  `json:"timestamp"`
	RequestTime int64   `json:"request_time"`
}

type GeocodeResponse struct {
	Results []struct {
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
		City      string  `json:"name"`
	} `json:"results"`
}

func main() {
	logger.LogInfo("Starting weather server...")
	server := jacked.New()

	// Health check endpoint
	server.GET("/api/health", func(c *jacked.Context) error {
		setSecurityHeaders(c.Response)
		health := map[string]interface{}{
			"status": "healthy",
			"uptime": metrics.GetUptime().String(),
			"metrics": map[string]interface{}{
				"total_requests":   atomic.LoadUint64(&metrics.TotalRequests),
				"failed_requests":  atomic.LoadUint64(&metrics.FailedRequests),
				"average_response": metrics.AverageResponse,
				"last_minute_hits": metrics.LastMinuteHits,
			},
		}
		return c.JSON(200, health)
	})

	// Metrics SSE endpoint
	server.GET("/api/metrics", func(c *jacked.Context) error {
		setSecurityHeaders(c.Response)
		c.Response.Header().Set("Content-Type", "text/event-stream")
		c.Response.Header().Set("Cache-Control", "no-cache")
		c.Response.Header().Set("Connection", "keep-alive")
		c.Response.Header().Set("X-Accel-Buffering", "no") // Disable proxy buffering

		// Create a channel to detect client disconnection
		done := make(chan bool)
		go func() {
			<-c.Request.Context().Done()
			done <- true
		}()

		// Send initial metrics
		metricsData := map[string]interface{}{
			"total_requests":   atomic.LoadUint64(&metrics.TotalRequests),
			"failed_requests":  atomic.LoadUint64(&metrics.FailedRequests),
			"average_response": metrics.AverageResponse,
			"last_minute_hits": metrics.LastMinuteHits,
			"uptime":           metrics.GetUptime().String(),
		}
		data, _ := json.Marshal(metricsData)
		fmt.Fprintf(c.Response, "data: %s\n\n", data)
		c.Response.(http.Flusher).Flush()

		// Keep connection alive and send updates
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				metricsData := map[string]interface{}{
					"total_requests":   atomic.LoadUint64(&metrics.TotalRequests),
					"failed_requests":  atomic.LoadUint64(&metrics.FailedRequests),
					"average_response": metrics.AverageResponse,
					"last_minute_hits": metrics.LastMinuteHits,
					"uptime":           metrics.GetUptime().String(),
				}
				data, _ := json.Marshal(metricsData)
				fmt.Fprintf(c.Response, "data: %s\n\n", data)
				c.Response.(http.Flusher).Flush()
			case <-done:
				return nil
			}
		}
	})

	// Weather endpoint
	server.GET("/api/weather", func(c *jacked.Context) error {
		start := time.Now()
		logger.LogRequest(c.Request.Method, c.Request.URL.Path, c.Request.RemoteAddr)
		setSecurityHeaders(c.Response)
		query := c.Request.URL.Query()
		lat := query.Get("lat")
		lon := query.Get("lon")
		city := query.Get("city")

		var latitude, longitude float64
		var cityName string
		var err error

		if city != "" {
			logger.LogInfo("Geocoding city: %s", city)
			// Geocode city to coordinates
			geocodeURL := fmt.Sprintf("https://geocoding-api.open-meteo.com/v1/search?name=%s&count=1", url.QueryEscape(city))

			// Validate URL
			parsedURL, err := validateURL(geocodeURL)
			if err != nil {
				logger.LogError(err, "Invalid geocoding URL")
				metrics.RecordRequest(time.Since(start), true)
				return c.BadRequest("Invalid geocoding URL")
			}

			// Create request with context
			req, err := http.NewRequestWithContext(c.Request.Context(), "GET", parsedURL.String(), nil)
			if err != nil {
				logger.LogError(err, "Failed to create geocoding request")
				metrics.RecordRequest(time.Since(start), true)
				return c.InternalServerError(fmt.Errorf("Failed to create geocoding request"))
			}

			// Add security headers
			req.Header.Set("User-Agent", "WeatherApp/1.0")
			req.Header.Set("Accept", "application/json")

			resp, err := httpClient.Do(req)
			if err != nil {
				logger.LogError(err, "Failed to geocode city")
				metrics.RecordRequest(time.Since(start), true)
				return c.InternalServerError(fmt.Errorf("Failed to geocode city"))
			}
			defer resp.Body.Close()

			var geocodeResp GeocodeResponse
			if err := json.NewDecoder(resp.Body).Decode(&geocodeResp); err != nil {
				logger.LogError(err, "Failed to parse geocoding response")
				metrics.RecordRequest(time.Since(start), true)
				return c.InternalServerError(fmt.Errorf("Failed to parse geocoding response"))
			}

			if len(geocodeResp.Results) == 0 {
				logger.LogInfo("City not found: %s", city)
				metrics.RecordRequest(time.Since(start), true)
				return c.NotFound("City not found")
			}

			latitude = geocodeResp.Results[0].Latitude
			longitude = geocodeResp.Results[0].Longitude
			cityName = geocodeResp.Results[0].City
			logger.LogInfo("Geocoded %s to lat: %.6f, lon: %.6f", city, latitude, longitude)
		} else {
			latitude, err = strconv.ParseFloat(lat, 64)
			if err != nil {
				logger.LogError(err, "Invalid latitude")
				metrics.RecordRequest(time.Since(start), true)
				return c.BadRequest("Invalid latitude")
			}
			longitude, err = strconv.ParseFloat(lon, 64)
			if err != nil {
				logger.LogError(err, "Invalid longitude")
				metrics.RecordRequest(time.Since(start), true)
				return c.BadRequest("Invalid longitude")
			}
			logger.LogInfo("Using coordinates: lat: %.6f, lon: %.6f", latitude, longitude)
		}

		// Fetch weather data from OpenMeteo
		weatherURL := fmt.Sprintf("https://api.open-meteo.com/v1/forecast?latitude=%.6f&longitude=%.6f&current=temperature_2m,relative_humidity_2m,wind_speed_10m,weather_code", latitude, longitude)
		logger.LogInfo("Fetching weather data from: %s", weatherURL)

		// Validate URL
		parsedURL, err := validateURL(weatherURL)
		if err != nil {
			logger.LogError(err, "Invalid weather URL")
			metrics.RecordRequest(time.Since(start), true)
			return c.BadRequest("Invalid weather URL")
		}

		// Create request with context
		req, err := http.NewRequestWithContext(c.Request.Context(), "GET", parsedURL.String(), nil)
		if err != nil {
			logger.LogError(err, "Failed to create weather request")
			metrics.RecordRequest(time.Since(start), true)
			return c.InternalServerError(fmt.Errorf("Failed to create weather request"))
		}

		// Add security headers
		req.Header.Set("User-Agent", "WeatherApp/1.0")
		req.Header.Set("Accept", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			logger.LogError(err, "Failed to fetch weather data")
			metrics.RecordRequest(time.Since(start), true)
			return c.InternalServerError(fmt.Errorf("Failed to fetch weather data"))
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.LogError(err, "Failed to read weather data")
			metrics.RecordRequest(time.Since(start), true)
			return c.InternalServerError(fmt.Errorf("Failed to read weather data"))
		}

		var weatherData map[string]interface{}
		if err := json.Unmarshal(body, &weatherData); err != nil {
			logger.LogError(err, "Failed to parse weather data")
			metrics.RecordRequest(time.Since(start), true)
			return c.InternalServerError(fmt.Errorf("Failed to parse weather data"))
		}

		current := weatherData["current"].(map[string]interface{})
		weatherCode := int(current["weather_code"].(float64))
		temperature := current["temperature_2m"].(float64)

		// Ensure wind speed is a valid number
		windSpeed, ok := current["wind_speed_10m"].(float64)
		if !ok {
			windSpeed = 0
		}

		weatherResponse := WeatherResponse{
			Temperature: temperature,
			Humidity:    current["relative_humidity_2m"].(float64),
			WindSpeed:   windSpeed,
			Description: getWeatherDescription(weatherCode),
			City:        cityName,
			Timestamp:   time.Now().Format(time.RFC3339),
			RequestTime: time.Since(start).Milliseconds(),
		}

		metrics.RecordRequest(time.Since(start), false)
		logger.LogWeather(cityName, latitude, longitude, temperature)
		return c.JSON(200, weatherResponse)
	})

	// Serve static files
	server.GET("/static/:filepath", func(c *jacked.Context) error {
		setSecurityHeaders(c.Response)
		filepath := c.Params.ByName("filepath")
		path := "static/" + filepath

		// Set proper MIME types
		switch {
		case strings.HasSuffix(path, ".css"):
			c.Response.Header().Set("Content-Type", "text/css")
		case strings.HasSuffix(path, ".js"):
			c.Response.Header().Set("Content-Type", "application/javascript")
		}

		http.ServeFile(c.Response, c.Request, path)
		return nil
	})

	// Serve index.html for root path
	server.GET("/", func(c *jacked.Context) error {
		logger.LogRequest(c.Request.Method, c.Request.URL.Path, c.Request.RemoteAddr)
		setSecurityHeaders(c.Response)
		http.ServeFile(c.Response, c.Request, "./static/index.html")
		return nil
	})

	logger.LogInfo("Server starting on :8080")
	if err := server.ListenAndServe(":8080"); err != nil {
		logger.LogError(err, "Server failed to start")
		os.Exit(1)
	}
}

func getWeatherDescription(code int) string {
	descriptions := map[int]string{
		0:  "Clear sky",
		1:  "Mainly clear",
		2:  "Partly cloudy",
		3:  "Overcast",
		45: "Foggy",
		48: "Depositing rime fog",
		51: "Light drizzle",
		53: "Moderate drizzle",
		55: "Dense drizzle",
		61: "Slight rain",
		63: "Moderate rain",
		65: "Heavy rain",
		71: "Slight snow",
		73: "Moderate snow",
		75: "Heavy snow",
		77: "Snow grains",
		80: "Slight rain showers",
		81: "Moderate rain showers",
		82: "Violent rain showers",
		85: "Slight snow showers",
		86: "Heavy snow showers",
		95: "Thunderstorm",
		96: "Thunderstorm with slight hail",
		99: "Thunderstorm with heavy hail",
	}

	if desc, ok := descriptions[code]; ok {
		return desc
	}
	return "Unknown"
}
