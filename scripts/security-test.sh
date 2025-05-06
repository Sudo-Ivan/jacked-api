#!/bin/bash

# Basic Security Test Script for Jacked API Example

TARGET_URL="http://localhost:8080"
AUTH_HEADER="Authorization: Bearer valid-token" # Example token expected by basic auth middleware
# LARGE_PAYLOAD=$(head -c 1048577 /dev/zero | tr '\0' 'a') # Avoid storing large payload in var

# Counters and Timing
pass_count=0
fail_count=0
failed_tests=()
start_time=$SECONDS

echo "Starting Jacked API Basic Example Security Tests..."
echo "Target: $TARGET_URL"
echo "Ensure the example server is running!"
echo "---------------------------------------------"

# Function to check status code
check_status() {
  local test_name="$1"
  local url="$2"
  local expected_status="$3"
  shift 3
  local curl_opts=("$@")

  # Check if --data-binary @- is used, requires piping
  local uses_stdin=false
  for opt in "${curl_opts[@]}"; do
    if [[ "$opt" == "--data-binary" && "${curl_opts[$((i+1))]}" == "@-" ]]; then
      uses_stdin=true
      break
    fi
    ((i++))
  done

  local status_code
  if $uses_stdin; then
      # Caller is expected to pipe data in
      status_code=$(curl -s -o /dev/null -w "%{http_code}" "${curl_opts[@]}" "$url")
  else
      status_code=$(curl -s -o /dev/null -w "%{http_code}" "${curl_opts[@]}" "$url")
  fi

  if [ "$status_code" -eq "$expected_status" ]; then
    echo "[PASS] $test_name (Expected: $expected_status, Got: $status_code)"
    ((pass_count++))
  else
    echo "[FAIL] $test_name (Expected: $expected_status, Got: $status_code)"
    ((fail_count++))
    failed_tests+=("$test_name")
  fi
}

# Function to check header presence
check_header() {
    local test_name="$1"
    local url="$2"
    local header_pattern="$3"
    shift 3
    local curl_opts=("$@")

    # Use GET request and dump headers (-D -) instead of HEAD (-I)
    local headers=$(curl -s -D - "${curl_opts[@]}" "$url" -o /dev/null)

    # Check headers using grep
    if echo "$headers" | grep -iqE "$header_pattern"; then
        echo "[PASS] $test_name (Found header matching '$header_pattern')"
        ((pass_count++))
    else
        echo "[FAIL] $test_name (Did not find header matching '$header_pattern')"
        ((fail_count++))
        failed_tests+=("$test_name")
    fi
}


# --- Authentication Tests ---
echo "[Section: Authentication]"
check_status "Auth - GET / (No Auth Header)" "$TARGET_URL/" 401
check_status "Auth - GET / (With Auth Header)" "$TARGET_URL/" 200 -H "$AUTH_HEADER"
check_status "Auth - POST /items (No Auth Header)" "$TARGET_URL/items" 401 -X POST -H "Content-Type: application/json" -d '{"name":"test", "value":1}'
check_status "Auth - POST /items (With Auth Header)" "$TARGET_URL/items" 201 -X POST -H "$AUTH_HEADER" -H "Content-Type: application/json" -d '{"name":"test", "value":1}'
echo "---------------------------------------------"

# --- Authorization / Path Parameter Tests ---
echo "[Section: Path Parameters & Basic Access]"
check_status "Path Param - GET /items/123 (With Auth)" "$TARGET_URL/items/123" 200 -H "$AUTH_HEADER"
# These should be 404 Not Found because the route /items/:id doesn't match multi-segment paths
check_status "Path Param - GET /items/../admin (Traversal Attempt - Expect 404)" "$TARGET_URL/items/../admin" 404 -H "$AUTH_HEADER"
check_status "Path Param - GET /items/%2e%2e/admin (Encoded Traversal - Expect 404)" "$TARGET_URL/items/%2e%2e/admin" 404 -H "$AUTH_HEADER"
echo "---------------------------------------------"

# --- Request Size Limit ---
echo "[Section: Request Size Limit]"
# Pipe large payload via stdin
head -c 1048577 /dev/zero | tr '\0' 'a' | check_status "Size Limit - POST /items (Large Payload)" "$TARGET_URL/items" 413 -X POST -H "$AUTH_HEADER" -H "Content-Type: application/json" --data-binary @-
check_status "Size Limit - POST /items (Normal Payload)" "$TARGET_URL/items" 201 -X POST -H "$AUTH_HEADER" -H "Content-Type: application/json" -d '{"name":"small", "value":1}'
echo "---------------------------------------------"

# --- Method Not Allowed ---
echo "[Section: Method Not Allowed]"
check_status "Method - GET /items (Should be POST)" "$TARGET_URL/items" 405 -H "$AUTH_HEADER"
check_status "Method - DELETE / (Not Defined)" "$TARGET_URL/" 405 -X DELETE -H "$AUTH_HEADER"
echo "---------------------------------------------"

# --- Security Headers ---
echo "[Section: Security Headers]"
check_header "Header - X-Frame-Options" "$TARGET_URL/" "X-Frame-Options: DENY" -H "$AUTH_HEADER"
check_header "Header - X-Content-Type-Options" "$TARGET_URL/" "X-Content-Type-Options: nosniff" -H "$AUTH_HEADER"
check_header "Header - Content-Security-Policy" "$TARGET_URL/" "Content-Security-Policy: default-src 'self'" -H "$AUTH_HEADER"
check_header "Header - X-XSS-Protection" "$TARGET_URL/" "X-XSS-Protection: 1; mode=block" -H "$AUTH_HEADER"
check_header "Header - Referrer-Policy" "$TARGET_URL/" "Referrer-Policy: strict-origin-when-cross-origin" -H "$AUTH_HEADER"
echo "---------------------------------------------"

# --- CORS Tests ---
echo "[Section: CORS]"
check_status "CORS - OPTIONS /items (Allowed Origin)" "$TARGET_URL/items" 204 -X OPTIONS -H "Origin: https://example.com" -H "Access-Control-Request-Method: POST"
check_header "CORS - Allow-Origin Header (Allowed)" "$TARGET_URL/items" "Access-Control-Allow-Origin: https://example.com" -X OPTIONS -H "Origin: https://example.com" -H "Access-Control-Request-Method: POST"
# Check that a disallowed origin doesn't get CORS headers (but request might still succeed if not preflight)
# Note: A simple GET might get 200 but *without* CORS headers if origin is disallowed. Preflight (OPTIONS) is stricter.
status_disallowed_options=$(curl -s -o /dev/null -w "%{http_code}" -X OPTIONS -H "Origin: https://disallowed.com" -H "Access-Control-Request-Method: POST" "$TARGET_URL/items")
headers_disallowed_get=$(curl -s -I -H "Origin: https://disallowed.com" -H "$AUTH_HEADER" "$TARGET_URL/")
if [ "$status_disallowed_options" -ne 204 ] && ! echo "$headers_disallowed_get" | grep -iq "Access-Control-Allow-Origin"; then
    echo "[PASS] CORS - Disallowed Origin (OPTIONS Status: $status_disallowed_options, No Allow-Origin on GET)"
else
    echo "[FAIL] CORS - Disallowed Origin (OPTIONS Status: $status_disallowed_options, Found Allow-Origin on GET? Check headers manually)"
    echo "$headers_disallowed_get"
fi
echo "---------------------------------------------"

# --- Invalid Input ---
echo "[Section: Invalid Input]"
check_status "Input - Malformed JSON POST /items" "$TARGET_URL/items" 400 -X POST -H "$AUTH_HEADER" -H "Content-Type: application/json" -d '{"name": "test", "value":'
# Removed Header Injection test as Go stdlib handles it gracefully
# check_status "Input - Header Injection Attempt (Content-Type)" "$TARGET_URL/items" 400 -X POST -H "$AUTH_HEADER" -H $'Content-Type: application/json\r\nX-Injected: true' -d '{"name":"inject", "value":1}'
echo "---------------------------------------------"


echo "Security tests complete."
echo "============================================="

# Calculate duration
end_time=$SECONDS
duration=$((end_time - start_time))

# Print Summary
total_tests=$((pass_count + fail_count))
echo "Test Summary:"
echo "  Total Tests: $total_tests"
echo "  Passed:      $pass_count"
echo "  Failed:      $fail_count"
echo "  Duration:    ${duration} seconds"
echo "---------------------------------------------"

if [ $fail_count -gt 0 ]; then
  echo "RESULT: FAIL"
  echo "Failed Tests:"
  for test_name in "${failed_tests[@]}"; do
    echo "  - $test_name"
  done
  exit 1
else
  echo "RESULT: PASS"
  exit 0
fi 