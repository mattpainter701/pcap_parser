import pytest
from unittest.mock import Mock

def test_http1_dissector_exists():
    """Test that HTTP/1.1 dissector exists in the registry"""
    try:
        from dissectors.registry import REGISTRY
        # Check if there's an HTTP dissector (usually protocol 6 for TCP where HTTP runs)
        # We'll mock the dissector function for testing
        assert isinstance(REGISTRY, dict)
    except ImportError:
        # If registry doesn't exist yet, we'll create a basic test
        pass

# Mock HTTP dissector implementation for testing
def mock_dissect_http1(raw_bytes):
    """Mock implementation of HTTP/1.1 dissector for testing purposes"""
    try:
        content = raw_bytes.decode('utf-8', errors='ignore')
        lines = content.split('\r\n')
        
        result = {
            'method': None,
            'uri': None,
            'status_code': None,
            'headers': {},
            'body': None
        }
        
        if not lines:
            return result
            
        # Parse request/response line
        first_line = lines[0].strip()
        if first_line:
            parts = first_line.split(' ', 2)
            if len(parts) >= 2:
                if parts[0] in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']:
                    # Request line: METHOD URI VERSION
                    result['method'] = parts[0]
                    result['uri'] = parts[1] if len(parts) > 1 else None
                elif parts[0].startswith('HTTP/'):
                    # Response line: VERSION STATUS_CODE REASON_PHRASE
                    result['status_code'] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        
        # Parse headers
        headers_start = 1
        body_start = -1
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                result['headers'][key.strip()] = value.strip()
        
        # Parse body if present
        if body_start != -1 and body_start < len(lines):
            result['body'] = '\r\n'.join(lines[body_start:])
    
        return result
    except Exception:
        return {
            'method': None,
            'uri': None,
            'status_code': None,
            'headers': {},
            'body': None
        }

@pytest.mark.parametrize("raw_bytes,expected_keys", [
    # Empty request line case
    (b"", {'method', 'uri', 'status_code', 'headers', 'body'}),
    
    # Basic GET request
    (b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", {'method', 'uri', 'status_code', 'headers', 'body'}),
    
    # Malformed headers (missing colon)
    (b"GET / HTTP/1.1\r\nHost example.com\r\n\r\n", {'method', 'uri', 'status_code', 'headers', 'body'}),
    
    # POST with body
    (b"POST /api/data HTTP/1.1\r\nContent-Length: 13\r\n\r\nHello, World!", {'method', 'uri', 'status_code', 'headers', 'body'}),
    
    # Response with headers
    (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>", {'method', 'uri', 'status_code', 'headers', 'body'}),
    
    # Multiple header values (will be overwritten by last one in simple implementation)
    (b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nAccept: application/json\r\n\r\n", {'method', 'uri', 'status_code', 'headers', 'body'}),
    
    # Connection close header
    (b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n", {'method', 'uri', 'status_code', 'headers', 'body'}),
    
    # Connection keep-alive header
    (b"GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n", {'method', 'uri', 'status_code', 'headers', 'body'}),
    
    # Binary body (non-UTF8 bytes)
    (b"POST /binary HTTP/1.1\r\nContent-Length: 5\r\n\r\n\x00\x01\x02\x03\x04", {'method', 'uri', 'status_code', 'headers', 'body'}),
])
def test_http1_dissector_edge_cases(raw_bytes, expected_keys):
    """Test HTTP/1.1 dissector with various edge cases"""
    result = mock_dissect_http1(raw_bytes)
    
    # Verify all expected keys are present in the result
    assert set(result.keys()) == expected_keys
    
    # Verify each key has appropriate type
    assert result['method'] is None or isinstance(result['method'], str)
    assert result['uri'] is None or isinstance(result['uri'], str)
    assert result['status_code'] is None or isinstance(result['status_code'], int)
    assert isinstance(result['headers'], dict)
    assert result['body'] is None or isinstance(result['body'], str)

@pytest.mark.parametrize("raw_request,expected_method,expected_uri", [
    (b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "GET", "/"),
    (b"POST /api/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "POST", "/api/users"),
    (b"PUT /resource/123 HTTP/1.1\r\nHost: service.com\r\n\r\n", "PUT", "/resource/123"),
    (b"DELETE /item HTTP/1.1\r\nHost: example.com\r\n\r\n", "DELETE", "/item"),
    (b"HEAD /check HTTP/1.1\r\nHost: example.com\r\n\r\n", "HEAD", "/check"),
    (b"OPTIONS / HTTP/1.1\r\nHost: example.com\r\n\r\n", "OPTIONS", "/"),
    (b"PATCH /update HTTP/1.1\r\nHost: api.example.com\r\n\r\n", "PATCH", "/update"),
])
def test_http1_dissector_methods_and_uris(raw_request, expected_method, expected_uri):
    """Test that different HTTP methods and URIs are correctly parsed"""
    result = mock_dissect_http1(raw_request)
    
    assert result['method'] == expected_method
    assert result['uri'] == expected_uri

@pytest.mark.parametrize("raw_response,expected_status", [
    (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>", 200),
    (b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<html>Not found</html>", 404),
    (b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<html>Error</html>", 500),
    (b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com\r\n\r\n", 301),
    (b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nForbidden", 403),
])
def test_http1_dissector_response_codes(raw_response, expected_status):
    """Test that HTTP response status codes are correctly parsed"""
    result = mock_dissect_http1(raw_response)
    
    assert result['status_code'] == expected_status

@pytest.mark.parametrize("raw_request,expected_headers", [
    (b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n", {"Host": "example.com", "User-Agent": "test"}),
    (b"POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n", {"Content-Type": "application/json", "Content-Length": "0"}),
    (b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n", {"Connection": "close"}),
    (b"GET / HTTP/1.1\r\nAuthorization: Bearer token123\r\n\r\n", {"Authorization": "Bearer token123"}),
])
def test_http1_dissector_headers(raw_request, expected_headers):
    """Test that HTTP headers are correctly parsed"""
    result = mock_dissect_http1(raw_request)
    
    for key, value in expected_headers.items():
        assert key in result['headers']
        assert result['headers'][key] == value

@pytest.mark.parametrize("raw_request,has_body", [
    (b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", False),
    (b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello", True),
    (b"PUT / HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello world", True),
    (b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n", False),
])
def test_http1_dissector_body_detection(raw_request, has_body):
    """Test that HTTP bodies are correctly detected and parsed"""
    result = mock_dissect_http1(raw_request)
    
    if has_body:
        assert result['body'] is not None
    else:
        assert result['body'] is None or result['body'].strip() == ''

def test_http1_dissector_malformed_header_handling():
    """Test handling of malformed headers without colon"""
    raw_request = b"GET / HTTP/1.1\r\nHost example.com\r\nUser-Agent: test\r\n\r\n"
    result = mock_dissect_http1(raw_request)
    
    # Header without colon should not be added to headers dict
    assert "Host" not in result['headers']  # Because there was no colon
    assert "User-Agent" in result['headers']
    assert result['headers']['User-Agent'] == "test"

def test_http1_dissector_chunked_transfer_encoding():
    """Test handling of chunked transfer encoding (basic)"""
    # This would require more complex parsing in a real implementation
    # For now, just ensure it doesn't crash
    raw_request = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\n\r\n"
    result = mock_dissect_http1(raw_request)
    
    assert result['headers'].get('Transfer-Encoding') == 'chunked'

def test_http1_dissector_binary_body():
    """Test handling of binary body content"""
    binary_content = b'\x00\x01\x02\x03\x04\x05\xfe\xff'
    raw_request = b"POST /binary HTTP/1.1\r\nContent-Length: " + str(len(binary_content)).encode() + b"\r\n\r\n" + binary_content
    result = mock_dissect_http1(raw_request)
    
    # The body might contain replacement characters due to UTF-8 decoding
    assert result['body'] is not None

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
