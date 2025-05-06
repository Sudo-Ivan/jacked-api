ARG EXAMPLE_NAME=basic
ARG TARGET_PLATFORM=linux_amd64

FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache make

COPY go.mod go.sum ./
RUN go mod download

COPY Makefile ./
COPY jacked/ ./jacked
COPY example/ ./example

RUN make build-release

FROM alpine:latest

ARG EXAMPLE_NAME
ARG TARGET_PLATFORM

WORKDIR /app

COPY --from=builder /app/dist/${EXAMPLE_NAME}_${TARGET_PLATFORM}_release /app/server

# The basic example runs on 8080, expose it.
# You might need to change this if running a different example.
EXPOSE 8080 

CMD ["/app/server"] 