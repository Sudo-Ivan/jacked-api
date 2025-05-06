# Jacked API

A minimal API framework in Go, Built for performance and simplicity.

## Features

- Minimal codebase and dependencies
- Built-in middleware support with chain handling
- JSON response helpers (`c.JSON`)
- HTML Template Rendering (`c.Render`)
- String Response Helper (`c.String`)
- Thread-safe routing with request pooling
- Graceful shutdown support
- Clean and intuitive API
- Middleware chain and context handling (`c.Next`, `c.Abort`)
- Route Parameter Access (`c.Param`)
- Query Parameter Helpers (`c.QueryString`, `c.QueryInt`, `c.QueryBool`)
- Error Handling Helpers (`c.AbortWithError`, `c.NotFound`, `c.BadRequest`, `c.InternalServerError`)
- Rate limiting

## Dependencies

```
github.com/goccy/go-json
github.com/julienschmidt/httprouter
```

## Installation
```bash
go install github.com/Sudo-Ivan/jacked-api@latest
```

## Quick Start

```go
package main

import (
    "log"
    "github.com/Sudo-Ivan/jacked-api"
)

func main() {
    app := jacked.New()

    // Add middleware
    app.Use(func(c *jacked.Context) error {
        // Your middleware logic here
        return c.Next() // Call next handler
    })

    app.GET("/", func(c *jacked.Context) error {
        return c.JSON(200, map[string]string{
            "message": "Welcome to Jacked API!",
        })
    })

    log.Fatal(app.ListenAndServe(":8080"))
}
```

## Command Line Flags

Jacked API provides built-in command-line flag support:

```bash
# Long flags
--port     Port to listen on (default: "8080")
--host     Host to listen on (default: "")
--debug    Enable debug mode (default: false)

# Short flags
-p         Port to listen on (shorthand)
-h         Host to listen on (shorthand)
-d         Enable debug mode (shorthand)
```

Example usage:
```bash
# Run with default settings
go run main.go

# Run on a specific port
go run main.go -p 3000

# Run with debug mode
go run main.go -d

# Run with all options
go run main.go -h localhost -p 3000 -d
```

## Docker Usage

You can build and run the provided examples using Docker.

### Build

The `Dockerfile` uses a multi-stage build. It first builds the specified example using the Go compiler and then copies the binary into a minimal Alpine image.

To build the image (this builds the `basic` example for `linux/amd64` by default):

```bash
docker build -f docker/Dockerfile -t my-jacked-app .
```

To build a specific example or target platform, use build arguments:

```bash
# Build the 'http' example for linux/arm64
docker build --build-arg EXAMPLE_NAME=http --build-arg TARGET_PLATFORM=linux_arm64 -f docker/Dockerfile -t my-jacked-http-app .
```

*(Note: See the `Makefile` for available examples and target platforms)*

### Run

Run the built container, mapping the appropriate port (the default examples use `8080`):

```bash
docker run -d -p 8080:8080 my-jacked-app
```

You can then access the application at `http://localhost:8080`.

## API Reference

### Server

```go
// Create a new server
app := jacked.New()

// Add middleware
app.Use(func(c *jacked.Context) error {
    // Your middleware logic here
    return c.Next() // Call next handler
})

// Register routes
app.GET("/path", handler)
app.POST("/path", handler)
app.PUT("/path", handler)
app.DELETE("/path", handler)

// Start the server
app.ListenAndServe(":8080")

// Graceful shutdown
app.Shutdown(ctx)
```

### Context

```go
// JSON response
c.JSON(200, data)

// Access request
c.Request.Method
c.Request.URL.Path

// Access response writer
c.Response.Write([]byte("Hello"))

// String response
c.String(200, "Hello, world!")

// HTML Template Rendering
// Assumes template files are parsed or accessible by the Render method.
// c.Render(200, "template.html", data)

// Parameter Handling
routeName := c.Param("name") // Get path parameter by name
queryName := c.QueryString("name", "Guest") // Get query parameter with default
queryAge := c.QueryInt("age", 0)
queryActive := c.QueryBool("active", false)

// Middleware chain control
c.Next()    // Call next handler
c.Abort()   // Stop the handler chain

// Error Handling Helpers
// c.AbortWithError(statusCode, err) // Aborts and sends a JSON error response
// c.NotFound("Resource not found")
// c.BadRequest("Invalid input")
// c.InternalServerError(err) // Logs server-side, sends generic error to client
```

### Concurrency

The framework includes built-in concurrency handling:
- Request pooling to limit concurrent connections
- Thread-safe routing and middleware execution
- Graceful shutdown support

## License

MIT 

