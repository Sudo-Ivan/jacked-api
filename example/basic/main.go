package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Sudo-Ivan/jacked-api/jacked"
)

func main() {
	// Create custom configuration
	config := &jacked.Config{
		ReadTimeout:           30 * time.Second,
		WriteTimeout:          30 * time.Second,
		IdleTimeout:           120 * time.Second,
		MaxConns:              2000,
		TrustedProxies:        []string{"127.0.0.1", "10.0.0.0/8"},
		AllowedOrigins:        []string{"https://example.com", "https://api.example.com"},
		AllowedMethods:        []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:        []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
		ExposedHeaders:        []string{"Content-Length", "X-Total-Count"},
		AllowCredentials:      true,
		MaxAge:                12 * time.Hour,
		MaxRequestSize:        1 << 20, // 1MB
		EnableCompression:     true,
		EnableSecurityHeaders: true,
	}

	// Create a new server instance with custom configuration
	app := jacked.NewWithConfig(config)

	// Add middleware for request logging
	app.Use(func(c *jacked.Context) error {
		start := time.Now()
		log.Printf("Request started: %s %s", c.Request.Method, c.Request.URL.Path)

		// Call next handler
		err := c.Next()

		// Log after request is complete
		log.Printf("Request completed: %s %s in %v", c.Request.Method, c.Request.URL.Path, time.Since(start))
		return err
	})

	// Add rate limiting middleware
	app.Use(func(c *jacked.Context) error {
		// Example rate limiting logic
		// In a real application, you would use a proper rate limiter
		// time.Sleep(100 * time.Millisecond) // Simulate rate limiting - REMOVED FOR PERFORMANCE TESTING
		return c.Next()
	})

	// Add authentication middleware
	app.Use(func(c *jacked.Context) error {
		// Allow OPTIONS requests to pass through without auth check (for CORS preflight)
		if c.Request.Method == http.MethodOptions {
			return c.Next()
		}

		// Example auth check
		if c.Request.Header.Get("Authorization") == "" {
			if err := c.JSON(401, map[string]string{"error": "unauthorized"}); err != nil {
				log.Printf("Error sending unauthorized response: %v", err)
				return err
			}
			c.Abort() // Stop the handler chain
			return nil
		}
		return c.Next()
	})

	// Define routes
	app.GET("/", func(c *jacked.Context) error {
		return c.JSON(200, map[string]string{
			"message": "Welcome to Jacked API!",
		})
	})

	app.GET("/health", func(c *jacked.Context) error {
		return c.JSON(200, map[string]string{
			"status": "jacked",
		})
	})

	// Example POST endpoint
	type Item struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	app.POST("/items", func(c *jacked.Context) error {
		var newItem Item
		// Use StreamJSON to parse the request body
		if err := c.StreamJSON(c.Request.Body, &newItem); err != nil {
			log.Printf("Error decoding item: %v", err)
			return c.JSON(400, map[string]string{"error": "invalid request body"})
		}
		log.Printf("Received item: %+v", newItem)
		// In a real app, you'd save this item to a database
		newItem.Value++ // Simulate some processing
		return c.JSON(201, newItem)
	})

	// Example GET endpoint with path parameter
	app.GET("/items/:id", func(c *jacked.Context) error {
		itemID := c.Param("id") // Use c.Param helper method
		log.Printf("Fetching item with ID: %s", itemID)
		// In a real app, fetch from DB based on itemID
		return c.JSON(200, map[string]string{
			"id":      itemID,
			"message": "Item details would go here",
		})
	})

	// Example PUT endpoint
	app.PUT("/items/:id", func(c *jacked.Context) error {
		itemID := c.Param("id") // Use c.Param helper method
		var updatedItem Item
		if err := c.StreamJSON(c.Request.Body, &updatedItem); err != nil {
			log.Printf("Error decoding item for update: %v", err)
			return c.JSON(400, map[string]string{"error": "invalid request body"})
		}
		log.Printf("Updating item %s with data: %+v", itemID, updatedItem)
		// In a real app, update the item in the database
		return c.JSON(200, updatedItem)
	})

	// Example DELETE endpoint
	app.DELETE("/items/:id", func(c *jacked.Context) error {
		itemID := c.Param("id") // Use c.Param helper method
		log.Printf("Deleting item with ID: %s", itemID)
		// In a real app, delete the item from the database

		// Send 204 No Content status directly
		c.Response.WriteHeader(http.StatusNoContent)
		return nil // Return nil as no body is sent for 204
	})

	// Start the server in a goroutine
	go func() {
		log.Println("Server starting on :8080")
		if err := app.ListenAndServe(":8080"); err != nil {
			log.Fatal(err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := app.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exiting")
}
