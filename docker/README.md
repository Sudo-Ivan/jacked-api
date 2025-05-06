# Docker Instructions

## Build

```bash
docker build -t jacked-server -f docker/Dockerfile .
```

## Run

```bash
docker run -d -p 8080:8080 jacked-server
```

## Build Binaries

```bash
docker build -t jacked-server -f docker/Dockerfile.build .

# Create a temporary container from the builder image
docker create --name temp-builder jacked-server-builder

# Copy the dist directory from the container to your current host directory
docker cp temp-builder:/app/dist ./dist

# Remove the temporary container
docker rm temp-builder
```
