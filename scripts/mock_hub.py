import http.server
import json
import sys
import os

class MockHubHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        """Handles the TrueSignal SDK synchronization handshake."""
        if self.path == '/api/v2/version':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            # The SDK expects a version object to confirm compatibility
            response = {"version": "1.0.0", "status": "operational"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
            print("[SYNC]       OK | Sensor handshake complete.")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        """Handles and validates the TrueSignal event contract."""
        content_length = int(self.headers.get('Content-Length') or 0)
        post_data = self.rfile.read(content_length)
        
        try:
            payload = json.loads(post_data.decode('utf-8'))
            
            if self.path == '/api/v2/event':
                # 1. Enforce the updated V1.0 Contract
                required_keys = [
                    "sensorId", "eventTrigger", "severity", "source", "target", "details"
                ]
                
                for key in required_keys:
                    if key not in payload:
                        print(f"[CONTRACT]   FAIL| Event rejected. Missing required key: '{key}'")
                        self.send_response(400)
                        self.end_headers()
                        return
                
                # 2. Enforce severity type (String enum or Int)
                valid_severities = ["info", "low", "medium", "high", "critical"]
                if payload['severity'] not in valid_severities:
                    print(f"[CONTRACT]   FAIL| Event rejected. Invalid severity: '{payload['severity']}'")
                    self.send_response(400)
                    self.end_headers()
                    return

                if not isinstance(payload['details'], dict):
                    print("[CONTRACT]   FAIL| Event rejected. 'details' must be a JSON object")
                    self.send_response(400)
                    self.end_headers()
                    return

                print(f"[EVENT]      OK | Trigger: {payload['eventTrigger']} from {payload['sensorId']}")
                print(json.dumps(payload, indent=2))

                self.send_response(200)
                self.end_headers()

                # CI success flag: only a contract-valid event counts, not a
                # heartbeat or offline notice.
                with open('/tmp/test_passed', 'w') as f:
                    f.write('success')

            elif self.path == '/api/v2/heartbeat':
                self.send_response(200)
                self.end_headers()
                print(f"[HEARTBEAT]  OK | Sensor: {payload.get('sensorId', 'unknown')}")

            elif self.path == '/api/v2/offline':
                self.send_response(200)
                self.end_headers()
                print(f"[OFFLINE]    OK | Sensor: {payload.get('sensorId', 'unknown')}")
            else:
                self.send_response(404)
                self.end_headers()


        except json.JSONDecodeError:
            print("[ERROR]      FAIL| Payload is not valid JSON.")
            self.send_response(400)
            self.end_headers()
        except Exception as e:
            print(f"[ERROR]      FAIL| Unexpected error: {e}")
            self.send_response(500)
            self.end_headers()

    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    print("--- TrueSignal Mock Hub ---")
    print("Listening on 0.0.0.0:8080...")
    print("Awaiting sensor connections for contract validation...")
    server = http.server.HTTPServer(('0.0.0.0', 8080), MockHubHandler)
    
    # We need to stay alive for at least two requests: 
    # 1. The GET sync from the SDK
    # 2. The POST alert from the sensor
    while True:
        server.handle_request()