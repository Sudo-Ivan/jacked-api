INFO: Make sure the example server is running: go run example/main.go
INFO: Press Ctrl+C to stop this script.
======================================================
 Testing: GET / (Authorized)
 Duration: 10s | Concurrency: 50
 Command: hey -z 10s -c 50 -m GET -H "Authorization: Bearer dummy-token-perf-test" http://localhost:8080/
------------------------------------------------------

Summary:
  Total:	10.0019 secs
  Slowest:	0.0000 secs
  Fastest:	0.0000 secs
  Average:	 NaN secs
  Requests/sec:	26959.2269
  

Response time histogram:


Latency distribution:

Details (average, fastest, slowest):
  DNS+dialup:	 NaN secs, 0.0000 secs, 0.0000 secs
  DNS-lookup:	 NaN secs, 0.0000 secs, 0.0000 secs
  req write:	 NaN secs, 0.0000 secs, 0.0000 secs
  resp wait:	 NaN secs, 0.0000 secs, 0.0000 secs
  resp read:	 NaN secs, 0.0000 secs, 0.0000 secs

Status code distribution:

Error distribution:
  [269644]	Get "http://localhost:8080/": dial tcp [::1]:8080: connect: connection refused


======================================================
 Testing: GET /health (Authorized)
 Duration: 10s | Concurrency: 50
 Command: hey -z 10s -c 50 -m GET -H "Authorization: Bearer dummy-token-perf-test" http://localhost:8080/health
------------------------------------------------------

Summary:
  Total:	10.0016 secs
  Slowest:	0.0000 secs
  Fastest:	0.0000 secs
  Average:	 NaN secs
  Requests/sec:	27344.3498
  

Response time histogram:


Latency distribution:

Details (average, fastest, slowest):
  DNS+dialup:	 NaN secs, 0.0000 secs, 0.0000 secs
  DNS-lookup:	 NaN secs, 0.0000 secs, 0.0000 secs
  req write:	 NaN secs, 0.0000 secs, 0.0000 secs
  resp wait:	 NaN secs, 0.0000 secs, 0.0000 secs
  resp read:	 NaN secs, 0.0000 secs, 0.0000 secs

Status code distribution:

Error distribution:
  [273488]	Get "http://localhost:8080/health": dial tcp [::1]:8080: connect: connection refused


======================================================
 Testing: POST /items (Authorized)
 Duration: 10s | Concurrency: 50
 Command: hey -z 10s -c 50 -m POST -H "Authorization: Bearer dummy-token-perf-test" -T "application/json" -d '{"name":"perf-test","value":1}' http://localhost:8080/items
------------------------------------------------------

Summary:
  Total:	10.0012 secs
  Slowest:	0.0000 secs
  Fastest:	0.0000 secs
  Average:	 NaN secs
  Requests/sec:	27332.6831
  

Response time histogram:


Latency distribution:

Details (average, fastest, slowest):
  DNS+dialup:	 NaN secs, 0.0000 secs, 0.0000 secs
  DNS-lookup:	 NaN secs, 0.0000 secs, 0.0000 secs
  req write:	 NaN secs, 0.0000 secs, 0.0000 secs
  resp wait:	 NaN secs, 0.0000 secs, 0.0000 secs
  resp read:	 NaN secs, 0.0000 secs, 0.0000 secs

Status code distribution:

Error distribution:
  [273360]	Post "http://localhost:8080/items": dial tcp [::1]:8080: connect: connection refused


======================================================
 Testing: GET /items/test-item-123 (Authorized)
 Duration: 10s | Concurrency: 50
 Command: hey -z 10s -c 50 -m GET -H "Authorization: Bearer dummy-token-perf-test" http://localhost:8080/items/test-item-123
------------------------------------------------------

Summary:
  Total:	10.0014 secs
  Slowest:	0.0000 secs
  Fastest:	0.0000 secs
  Average:	 NaN secs
  Requests/sec:	27532.8562
  

Response time histogram:


Latency distribution:

Details (average, fastest, slowest):
  DNS+dialup:	 NaN secs, 0.0000 secs, 0.0000 secs
  DNS-lookup:	 NaN secs, 0.0000 secs, 0.0000 secs
  req write:	 NaN secs, 0.0000 secs, 0.0000 secs
  resp wait:	 NaN secs, 0.0000 secs, 0.0000 secs
  resp read:	 NaN secs, 0.0000 secs, 0.0000 secs

Status code distribution:

Error distribution:
  [275368]	Get "http://localhost:8080/items/test-item-123": dial tcp [::1]:8080: connect: connection refused


======================================================
 Testing: PUT /items/test-item-123 (Authorized)
 Duration: 10s | Concurrency: 50
 Command: hey -z 10s -c 50 -m PUT -H "Authorization: Bearer dummy-token-perf-test" -T "application/json" -d '{"name":"perf-test-updated","value":2}' http://localhost:8080/items/test-item-123
------------------------------------------------------

Summary:
  Total:	10.0014 secs
  Slowest:	0.0000 secs
  Fastest:	0.0000 secs
  Average:	 NaN secs
  Requests/sec:	27449.9763
  

Response time histogram:


Latency distribution:

Details (average, fastest, slowest):
  DNS+dialup:	 NaN secs, 0.0000 secs, 0.0000 secs
  DNS-lookup:	 NaN secs, 0.0000 secs, 0.0000 secs
  req write:	 NaN secs, 0.0000 secs, 0.0000 secs
  resp wait:	 NaN secs, 0.0000 secs, 0.0000 secs
  resp read:	 NaN secs, 0.0000 secs, 0.0000 secs

Status code distribution:

Error distribution:
  [274538]	Put "http://localhost:8080/items/test-item-123": dial tcp [::1]:8080: connect: connection refused


======================================================
 Testing: DELETE /items/test-item-123 (Authorized)
 Duration: 10s | Concurrency: 50
 Command: hey -z 10s -c 50 -m DELETE -H "Authorization: Bearer dummy-token-perf-test" http://localhost:8080/items/test-item-123
------------------------------------------------------

Summary:
  Total:	10.0011 secs
  Slowest:	0.0000 secs
  Fastest:	0.0000 secs
  Average:	 NaN secs
  Requests/sec:	27476.7961
  

Response time histogram:


Latency distribution:

Details (average, fastest, slowest):
  DNS+dialup:	 NaN secs, 0.0000 secs, 0.0000 secs
  DNS-lookup:	 NaN secs, 0.0000 secs, 0.0000 secs
  req write:	 NaN secs, 0.0000 secs, 0.0000 secs
  resp wait:	 NaN secs, 0.0000 secs, 0.0000 secs
  resp read:	 NaN secs, 0.0000 secs, 0.0000 secs

Status code distribution:

Error distribution:
  [274799]	Delete "http://localhost:8080/items/test-item-123": dial tcp [::1]:8080: connect: connection refused


======================================================
 Performance testing complete.
======================================================
