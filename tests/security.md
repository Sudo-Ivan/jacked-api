Starting Jacked API Basic Example Security Tests...
Target: http://localhost:8080
Ensure the example server is running!
---------------------------------------------
[Section: Authentication]
[FAIL] Auth - GET / (No Auth Header) (Expected: 401, Got: 000)
[FAIL] Auth - GET / (With Auth Header) (Expected: 200, Got: 000)
[FAIL] Auth - POST /items (No Auth Header) (Expected: 401, Got: 000)
[FAIL] Auth - POST /items (With Auth Header) (Expected: 201, Got: 000)
---------------------------------------------
[Section: Path Parameters & Basic Access]
[FAIL] Path Param - GET /items/123 (With Auth) (Expected: 200, Got: 000)
[FAIL] Path Param - GET /items/../admin (Traversal Attempt - Expect 404) (Expected: 404, Got: 000)
[FAIL] Path Param - GET /items/%2e%2e/admin (Encoded Traversal - Expect 404) (Expected: 404, Got: 000)
---------------------------------------------
[Section: Request Size Limit]
[FAIL] Size Limit - POST /items (Large Payload) (Expected: 413, Got: 000)
[FAIL] Size Limit - POST /items (Normal Payload) (Expected: 201, Got: 000)
---------------------------------------------
[Section: Method Not Allowed]
[FAIL] Method - GET /items (Should be POST) (Expected: 405, Got: 000)
[FAIL] Method - DELETE / (Not Defined) (Expected: 405, Got: 000)
---------------------------------------------
[Section: Security Headers]
[FAIL] Header - X-Frame-Options (Did not find header matching 'X-Frame-Options: DENY')
[FAIL] Header - X-Content-Type-Options (Did not find header matching 'X-Content-Type-Options: nosniff')
[FAIL] Header - Content-Security-Policy (Did not find header matching 'Content-Security-Policy: default-src 'self'')
[FAIL] Header - X-XSS-Protection (Did not find header matching 'X-XSS-Protection: 1; mode=block')
[FAIL] Header - Referrer-Policy (Did not find header matching 'Referrer-Policy: strict-origin-when-cross-origin')
---------------------------------------------
[Section: CORS]
[FAIL] CORS - OPTIONS /items (Allowed Origin) (Expected: 204, Got: 000)
[FAIL] CORS - Allow-Origin Header (Allowed) (Did not find header matching 'Access-Control-Allow-Origin: https://example.com')
[PASS] CORS - Disallowed Origin (OPTIONS Status: 000, No Allow-Origin on GET)
---------------------------------------------
[Section: Invalid Input]
[FAIL] Input - Malformed JSON POST /items (Expected: 400, Got: 000)
---------------------------------------------
Security tests complete.
=============================================
Test Summary:
  Total Tests: 18
  Passed:      0
  Failed:      18
  Duration:    0 seconds
---------------------------------------------
RESULT: FAIL
Failed Tests:
  - Auth - GET / (No Auth Header)
  - Auth - GET / (With Auth Header)
  - Auth - POST /items (No Auth Header)
  - Auth - POST /items (With Auth Header)
  - Path Param - GET /items/123 (With Auth)
  - Path Param - GET /items/../admin (Traversal Attempt - Expect 404)
  - Path Param - GET /items/%2e%2e/admin (Encoded Traversal - Expect 404)
  - Size Limit - POST /items (Normal Payload)
  - Method - GET /items (Should be POST)
  - Method - DELETE / (Not Defined)
  - Header - X-Frame-Options
  - Header - X-Content-Type-Options
  - Header - Content-Security-Policy
  - Header - X-XSS-Protection
  - Header - Referrer-Policy
  - CORS - OPTIONS /items (Allowed Origin)
  - CORS - Allow-Origin Header (Allowed)
  - Input - Malformed JSON POST /items
