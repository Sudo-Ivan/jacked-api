package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Sudo-Ivan/jacked-api/jacked"
)

func main() {
	// Use default configuration for simplicity
	app := jacked.New()

	// Directory containing static files (relative to project root)
	staticDir := "./example/http/public"

	// --- Serving files from the root URL ("/") ---
	// Create a file server handler - Removed unused variable
	// fileServerRoot := http.FileServer(http.Dir(staticDir))

	// Need to adapt http.Handler for httprouter.Handle
	// We can use httprouter.NotFound for this specific case if we want to serve index.html from root
	// Alternatively, register specific files or use a more complex setup.
	// For simplicity, let's serve index.html explicitly at root.
	app.GET("/", func(c *jacked.Context) error {
		start := time.Now() // Start timer
		filePath := staticDir + "/index.html"
		log.Printf("Serving file for /: %s", filePath)
		http.ServeFile(c.Response, c.Request, filePath)
		duration := time.Since(start) // Calculate duration
		log.Printf("Served file for / in %v", duration)
		return nil // ServeFile handles errors internally by writing HTTP errors
	})

	// --- Serving files from a specific path (e.g., "/static/") ---
	// Create a file server for the /static/ path - Removed unused variable
	// StripPrefix removes "/static/" so FileServer looks in the correct directory
	// fileServerStatic := http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir)))

	// httprouter needs a path with a wildcard for serving multiple files in a directory
	// The path must end with *filepath
	staticPath := "/static/*filepath"

	// Use router.Handler directly to register the standard http.Handler
	// Note: This bypasses jacked middleware for these static routes.
	app.GET(staticPath, func(c *jacked.Context) error {
		start := time.Now() // Start timer
		// Delegate to the standard http file server
		// Need to adjust the request URL path if using StripPrefix directly within handler
		// Or, register the handler directly using app.router.Handler

		log.Printf("Serving static file for path: %s", c.Request.URL.Path)

		// Re-fetch the file server to ensure correct prefix stripping for this request
		fs := http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir)))
		fs.ServeHTTP(c.Response, c.Request)
		duration := time.Since(start) // Calculate duration
		log.Printf("Served static file for path %s in %v", c.Request.URL.Path, duration)
		return nil // ServeHTTP handles writing response/errors
	})

	// Start the server in a goroutine
	go func() {
		log.Println("Static server starting on :8081")
		if err := app.ListenAndServe(":8081"); err != nil {
			log.Fatal(err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down static server...")
	// Shutdown is not implemented in this simplified example for brevity,
	// but you would add it similar to main.go if needed.
	// ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// defer cancel()
	// if err := app.Shutdown(ctx); err != nil {
	// 	log.Fatal("Server forced to shutdown:", err)
	// }

	log.Println("Static server exiting")
}
