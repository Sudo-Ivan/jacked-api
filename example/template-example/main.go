package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Sudo-Ivan/jacked-api/jacked"
)

// PageData struct for passing data to the HTML template.
type PageData struct {
	Title    string
	Message  string
	Name     string
	Time     string
	Features []string
}

// setSecurityHeaders sets appropriate security headers for the template example.
func setSecurityHeaders(w http.ResponseWriter) {
	csp := "default-src 'self'; " +
		"script-src 'self'; " + // No external scripts in this example yet
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " + // Allow inline styles and Google Fonts CSS
		"font-src 'self' https://fonts.gstatic.com https://fonts.googleapis.com; " + // Allow Google Fonts
		"img-src 'self' data:; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'; " +
		"block-all-mixed-content; " +
		"upgrade-insecure-requests;"

	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
}

func main() {
	// Create a new Jacked server instance.
	server := jacked.New()

	// Define a route for handling greetings with a dynamic name parameter.
	server.GET("/greet/:name", func(c *jacked.Context) error {
		setSecurityHeaders(c.Response) // Apply security headers
		name := c.Param("name")
		// If no name is provided, default to "Guest".
		if name == "" {
			name = "Guest"
		}

		// Populate the PageData struct with dynamic content.
		data := PageData{
			Title:   fmt.Sprintf("Greetings, %s!", name),
			Message: "Welcome to our enhanced template example!",
			Name:    name,
			Time:    time.Now().Format(time.RFC1123),
			Features: []string{
				"Dynamic Content Rendering",
				"Easy Parameter Handling",
				"Looping Over Data",
				"Cooler Styling!",
			},
		}

		// Render the HTML template with the provided data.
		err := c.Render(http.StatusOK, "templates/hello.html", data)
		if err != nil {
			log.Printf("Error rendering template: %v", err)
			return nil
		}
		return nil
	})

	// Define a route for the root path that returns a simple string.
	server.GET("/", func(c *jacked.Context) error {
		setSecurityHeaders(c.Response) // Apply security headers
		return c.String(http.StatusOK, "Template example server. Try /greet/YourName")
	})

	// Start the server and listen for incoming requests.
	fmt.Println("Server starting on :8081...")
	fmt.Println("Try: http://localhost:8081/greet/Jack")
	if err := server.ListenAndServe(":8081"); err != nil {
		log.Fatalf("Server failed to start: %v", err)
		os.Exit(1)
	}
}
