#!/bin/bash

# Performance Test Script for Jacked API Example

BASE_URL="http://localhost:8080"
DURATION="10s" # Duration for each test run (e.g., 10s, 1m)
CONCURRENCY=50 # Number of concurrent workers

# --- Helper function to print header ---
print_header() {
  echo "======================================================"
  echo " Testing: $1"
  echo " Duration: $DURATION | Concurrency: $CONCURRENCY"
  echo " Command: $2"
  echo "------------------------------------------------------"
}

# --- Ensure server is running ---
echo "INFO: Make sure the example server is running: go run example/main.go"
echo "INFO: Press Ctrl+C to stop this script."
sleep 3 # Give user time to read

# --- Define Auth Header ---
# Note: Using a fixed dummy token as per the example middleware
AUTH_HEADER="Authorization: Bearer dummy-token-perf-test"

# === Test Cases ===

# 1. GET / (Authorized)
CMD_GET_ROOT="hey -z $DURATION -c $CONCURRENCY -m GET -H \"$AUTH_HEADER\" $BASE_URL/"
print_header "GET / (Authorized)" "$CMD_GET_ROOT"
eval $CMD_GET_ROOT
echo ""

# 2. GET /health (Authorized)
CMD_GET_HEALTH="hey -z $DURATION -c $CONCURRENCY -m GET -H \"$AUTH_HEADER\" $BASE_URL/health"
print_header "GET /health (Authorized)" "$CMD_GET_HEALTH"
eval $CMD_GET_HEALTH
echo ""

# 3. POST /items (Authorized)
CMD_POST_ITEMS="hey -z $DURATION -c $CONCURRENCY -m POST -H \"$AUTH_HEADER\" -T \"application/json\" -d '{\"name\":\"perf-test\",\"value\":1}' $BASE_URL/items"
print_header "POST /items (Authorized)" "$CMD_POST_ITEMS"
eval $CMD_POST_ITEMS
echo ""

# 4. GET /items/:id (Authorized)
# Using a static ID for the test
ITEM_ID="test-item-123"
CMD_GET_ITEM="hey -z $DURATION -c $CONCURRENCY -m GET -H \"$AUTH_HEADER\" $BASE_URL/items/$ITEM_ID"
print_header "GET /items/$ITEM_ID (Authorized)" "$CMD_GET_ITEM"
eval $CMD_GET_ITEM
echo ""

# 5. PUT /items/:id (Authorized)
CMD_PUT_ITEM="hey -z $DURATION -c $CONCURRENCY -m PUT -H \"$AUTH_HEADER\" -T \"application/json\" -d '{\"name\":\"perf-test-updated\",\"value\":2}' $BASE_URL/items/$ITEM_ID"
print_header "PUT /items/$ITEM_ID (Authorized)" "$CMD_PUT_ITEM"
eval $CMD_PUT_ITEM
echo ""

# 6. DELETE /items/:id (Authorized)
CMD_DELETE_ITEM="hey -z $DURATION -c $CONCURRENCY -m DELETE -H \"$AUTH_HEADER\" $BASE_URL/items/$ITEM_ID"
print_header "DELETE /items/$ITEM_ID (Authorized)" "$CMD_DELETE_ITEM"
eval $CMD_DELETE_ITEM
echo ""


echo "======================================================"
echo " Performance testing complete."
echo "======================================================"