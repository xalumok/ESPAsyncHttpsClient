#pragma once
#include <Arduino.h>

#if defined(ESP8266)
  #include <ESP8266WiFi.h>
  #include <WiFiClientSecureBearSSL.h>
  #include <time.h>
  using SecureClientT = BearSSL::WiFiClientSecure;
#elif defined(ESP32)
  #include <WiFi.h>
  #include <WiFiClientSecure.h>
  #include <time.h>
  using SecureClientT = WiFiClientSecure;
#else
  #error "AsyncHttpsClient supports only ESP8266 or ESP32"
#endif

class AsyncHttpsClient {
public:
  enum Method : uint8_t { M_GET, M_POST };
  enum State  : uint8_t { IDLE, CONNECT, SEND, READ_HEADERS, READ_BODY, DONE, ERROR };

  struct Options {
    uint32_t timeoutMs           = 15000;  // overall request timeout
    uint16_t tlsHandshakeTimeout = 12000;  // handshake/socket timeout (coarse)
    size_t   maxHeaderBytes      = 4096;   // protect RAM
    size_t   maxBodyBytes        = 16 * 1024; // default body buffer limit (can stream instead)
    size_t   ioChunkSize         = 512;    // read buffer size
    bool     keepBody            = true;   // set false to stream-only
  };

  AsyncHttpsClient() = default;
  virtual ~AsyncHttpsClient() { stop(); }

  // ---------- REQUIRED for TLS security ----------
  // Provide a CA certificate (PEM). This is used for verification.
  // Put your CA cert in PROGMEM using a raw string literal.
  void setCACert(const char* caPem) {
    _caPem = caPem;
    _hasCa = (caPem && caPem[0]);
#if defined(ESP8266)
    // Create/replace trust anchors. X509List copies/parses the PEM.
    _ta.reset(new BearSSL::X509List(_caPem));
#endif
  }

  // TLS cert validation requires correct time.
  // Call after SNTP sync, or explicitly set epoch seconds.
  void setUnixTime(time_t nowEpoch) { _nowEpoch = nowEpoch; _hasTime = (nowEpoch > 1600000000); }

  void setOptions(const Options& opt) { _opt = opt; }

  // ---------- Requests ----------
  // path must include query if needed, e.g. "/v1/ping?x=1"
  bool beginGet(const String& host, uint16_t port, const String& path,
                const String& extraHeaders = "") {
    return beginRequest(M_GET, host, port, path, "", "", extraHeaders);
  }

  bool beginPost(const String& host, uint16_t port, const String& path,
                 const String& body, const String& contentType = "application/json",
                 const String& extraHeaders = "") {
    return beginRequest(M_POST, host, port, path, body, contentType, extraHeaders);
  }

  // Pump the request. Call often from loop().
  void poll() {
    if (_state == IDLE || _state == DONE || _state == ERROR) return;

#if defined(ESP8266)
    yield();
#else
    delay(0);
#endif

    if (millis() - _t0 > _opt.timeoutMs) {
      fail("timeout");
      return;
    }

    switch (_state) {
      case CONNECT:       stepConnect(); break;
      case SEND:          stepSend(); break;
      case READ_HEADERS:  stepReadHeaders(); break;
      case READ_BODY:     stepReadBody(); break;
      default:            break;
    }
  }

  // ---------- Status / results ----------
  bool done()  const { return _state == DONE; }
  bool error() const { return _state == ERROR; }
  State state() const { return _state; }

  int status() const { return _httpStatus; }
  const String& errorMsg() const { return _err; }

  // If keepBody==true and response <= maxBodyBytes, this returns it.
  const String& body() const { return _body; }

  // Stop/Reset
  void stop() {
    _client.stop();
    _state = IDLE;
  }

  void reset() {
    stop();
    _err = "";
    _httpStatus = -1;
    _body = "";
    _bodyOverflow = false;
    _req = "";
    _headerBytes = 0;
    _contentLength = -1;
    _chunked = false;
    _seenHeaderEnd = false;
    _line = "";
    _chunkState = CHUNK_SIZE;
    _chunkRemaining = 0;
    _chunkLine = "";
  }

protected:
  // Override to stream body chunks (recommended for large responses).
  // Return false to abort.
  virtual bool onBodyChunk(const uint8_t* data, size_t len) {
    if (!_opt.keepBody) return true;

    // Enforce maxBodyBytes
    if (_body.length() + len > _opt.maxBodyBytes) {
      // keep what we have, but signal overflow
      _bodyOverflow = true;
      return false; // abort to protect RAM (prod-friendly behavior)
    }

    // Append efficiently
    _body.reserve(_body.length() + len);
    for (size_t i = 0; i < len; i++) _body += char(data[i]);
    return true;
  }

private:
  // ---------- Internal ----------
  bool beginRequest(Method m,
                    const String& host, uint16_t port, const String& path,
                    const String& body, const String& contentType,
                    const String& extraHeaders) {
    reset();

    // Enforce TLS-secure prerequisites
    if (!_hasCa) { fail("TLS CA cert not set (setCACert)"); return false; }
    if (!_hasTime) { fail("System time not set (setUnixTime / SNTP)"); return false; }

    _method = m;
    _host = host;
    _port = port;
    _path = path;

    // Configure TLS verification
#if defined(ESP8266)
    _client.setBufferSizes(512, 512); // reasonable defaults
    _client.setTimeout(_opt.tlsHandshakeTimeout / 1000);
    _client.setX509Time(_nowEpoch); // critical for cert validity checks
    _client.setTrustAnchors(_ta.get());
#elif defined(ESP32)
    _client.setTimeout(_opt.tlsHandshakeTimeout / 1000);
    _client.setCACert(_caPem);
#endif

    // Build HTTP/1.1 request
    // (Connection: close simplifies correctness; you can add keep-alive later)
    _req.reserve(256 + body.length() + extraHeaders.length());
    _req += (m == M_GET ? F("GET ") : F("POST "));
    _req += path;
    _req += F(" HTTP/1.1\r\nHost: ");
    _req += host;
    _req += F("\r\nUser-Agent: esp-secure/1.0\r\nAccept: */*\r\nConnection: close\r\n");

    if (extraHeaders.length() > 0) {
      // Caller must include proper CRLF lines, e.g. "Authorization: Bearer ...\r\n"
      _req += extraHeaders;
      // Ensure it ends with CRLF (we'll be forgiving)
      if (!extraHeaders.endsWith("\r\n")) _req += F("\r\n");
    }

    if (m == M_POST) {
      _req += F("Content-Type: ");
      _req += contentType;
      _req += F("\r\nContent-Length: ");
      _req += String(body.length());
      _req += F("\r\n\r\n");
      _req += body;
    } else {
      _req += F("\r\n");
    }

    _t0 = millis();
    _state = CONNECT;
    return true;
  }

  void stepConnect() {
    if (_client.connected()) {
      _state = SEND;
      return;
    }

    // DNS + TCP + TLS handshake is inside connect() for secure client.
    if (!_client.connect(_host.c_str(), _port)) {
      fail("connect/TLS failed");
      return;
    }

    _state = SEND;
  }

  void stepSend() {
    if (!_client.connected()) {
      fail("socket closed before send");
      return;
    }

    size_t w = _client.print(_req);
    if (w == 0) {
      fail("send failed");
      return;
    }
    _state = READ_HEADERS;
  }

  void stepReadHeaders() {
    if (!_client.connected() && !_client.available()) {
      fail("closed during headers");
      return;
    }

    // Read header bytes and parse lines until \r\n\r\n
    while (_client.available()) {
      int c = _client.read();
      if (c < 0) break;

      _headerBytes++;
      if (_headerBytes > _opt.maxHeaderBytes) {
        fail("headers too large");
        return;
      }

      char ch = char(c);
      _line += ch;

      // line buffer protection
      if (_line.length() > 512) {
        fail("header line too long");
        return;
      }

      // Detect end of line
      if (ch == '\n') {
        String line = _line;
        _line = "";

        line.trim(); // removes \r\n and whitespace

        if (line.length() == 0) {
          _seenHeaderEnd = true;
          _state = READ_BODY;
          return;
        }

        // Status line
        if (line.startsWith("HTTP/1.1") && line.length() >= 12) {
          _httpStatus = line.substring(9, 12).toInt();
          continue;
        }

        // Headers we care about
        // Content-Length
        if (startsWithNoCase(line, "Content-Length:")) {
          String v = line.substring(strlen("Content-Length:"));
          v.trim();
          _contentLength = v.toInt();
          continue;
        }

        // Transfer-Encoding: chunked
        if (startsWithNoCase(line, "Transfer-Encoding:")) {
          if (containsNoCase(line, "chunked")) _chunked = true;
          continue;
        }
      }
    }
  }

  void stepReadBody() {
    if (!_seenHeaderEnd) return;

    if (_chunked) {
      stepReadChunkedBody();
      return;
    }

    // Non-chunked body (Content-Length or until close)
    uint8_t bufLocal[768];
    const size_t bufSz = min<size_t>(_opt.ioChunkSize, sizeof(bufLocal));

    while (_client.available()) {
#if defined(ESP8266)
      int n = _client.readBytes((char*)bufLocal, bufSz);
#else
      int n = _client.read(bufLocal, bufSz);
#endif
      if (n <= 0) break;

      if (!onBodyChunk(bufLocal, (size_t)n)) {
        fail(_bodyOverflow ? "body exceeded maxBodyBytes" : "body handler aborted");
        return;
      }
    }

    if (!_client.connected() && !_client.available()) {
      _client.stop();
      _state = DONE;
    }
  }

  // -------- Chunked decoding (minimal, robust enough for typical APIs) --------
  enum ChunkState : uint8_t { CHUNK_SIZE, CHUNK_DATA, CHUNK_CRLF, CHUNK_DONE };

  void stepReadChunkedBody() {
    uint8_t bufLocal[768];
    const size_t bufSz = min<size_t>(_opt.ioChunkSize, sizeof(bufLocal));

    while (_client.available()) {
      int c = _client.read();
      if (c < 0) break;
      char ch = char(c);

      switch (_chunkState) {
        case CHUNK_SIZE: {
          // Read hex size line until \n
          if (ch == '\n') {
            _chunkLine.trim(); // remove \r and spaces
            // ignore chunk extensions: "A;ext=1"
            int semi = _chunkLine.indexOf(';');
            String sizeStr = (semi >= 0) ? _chunkLine.substring(0, semi) : _chunkLine;
            sizeStr.trim();

            _chunkRemaining = (size_t) strtoul(sizeStr.c_str(), nullptr, 16);
            _chunkLine = "";

            if (_chunkRemaining == 0) {
              _chunkState = CHUNK_DONE;
              // consume trailing headers (optional) until close or empty line
              // We'll just finish once socket closes or no data; many servers close after 0-chunk.
            } else {
              _chunkState = CHUNK_DATA;
            }
          } else {
            _chunkLine += ch;
            if (_chunkLine.length() > 64) { fail("chunk size line too long"); return; }
          }
        } break;

        case CHUNK_DATA: {
          // We already consumed one byte (ch) of data; handle it plus bulk reads
          uint8_t one = (uint8_t)ch;
          if (!onBodyChunk(&one, 1)) { fail(_bodyOverflow ? "body exceeded maxBodyBytes" : "body handler aborted"); return; }
          _chunkRemaining--;

          // Bulk read more if available
          while (_chunkRemaining > 0 && _client.available()) {
            size_t want = min(_chunkRemaining, bufSz);
#if defined(ESP8266)
            int n = _client.readBytes((char*)bufLocal, want);
#else
            int n = _client.read(bufLocal, want);
#endif
            if (n <= 0) break;

            if (!onBodyChunk(bufLocal, (size_t)n)) { fail(_bodyOverflow ? "body exceeded maxBodyBytes" : "body handler aborted"); return; }
            _chunkRemaining -= (size_t)n;
          }

          if (_chunkRemaining == 0) _chunkState = CHUNK_CRLF;
        } break;

        case CHUNK_CRLF: {
          // Expect \r\n after chunk data; tolerate extra CRLF
          if (ch == '\n') _chunkState = CHUNK_SIZE;
        } break;

        case CHUNK_DONE: {
          // Some servers send trailing headers after 0-chunk; we can just finish on close.
          // If connection closes, we finish.
          // If it stays open, we still treat DONE when no more bytes and not connected.
        } break;
      }
    }

    if (!_client.connected() && !_client.available()) {
      _client.stop();
      _state = DONE;
    }
  }

  // -------- Helpers --------
  static bool startsWithNoCase(const String& s, const char* prefix) {
    size_t n = strlen(prefix);
    if (s.length() < n) return false;
    for (size_t i = 0; i < n; i++) {
      char a = s[i], b = prefix[i];
      if (a >= 'A' && a <= 'Z') a = char(a - 'A' + 'a');
      if (b >= 'A' && b <= 'Z') b = char(b - 'A' + 'a');
      if (a != b) return false;
    }
    return true;
  }

  static bool containsNoCase(const String& s, const char* needle) {
    String hay = s; hay.toLowerCase();
    String ned = needle; ned.toLowerCase();
    return hay.indexOf(ned) >= 0;
  }

  void fail(const char* msg) { _err = msg; _state = ERROR; _client.stop(); }
  void fail(const String& msg) { _err = msg; _state = ERROR; _client.stop(); }

private:
  SecureClientT _client;
  Options _opt;

  Method _method = M_GET;
  State  _state  = IDLE;

  String _host, _path;
  uint16_t _port = 443;

  // TLS prerequisites
  const char* _caPem = nullptr;
  bool _hasCa = false;

  time_t _nowEpoch = 0;
  bool _hasTime = false;

#if defined(ESP8266)
  // Trust anchors for BearSSL
  std::unique_ptr<BearSSL::X509List> _ta;
#endif

  // Request/Response parsing
  String _req;
  String _line;
  String _err;
  String _body;
  bool _bodyOverflow = false;

  int _httpStatus = -1;

  size_t _headerBytes = 0;
  int32_t _contentLength = -1;
  bool _chunked = false;
  bool _seenHeaderEnd = false;

  uint32_t _t0 = 0;

  // chunked
  ChunkState _chunkState = CHUNK_SIZE;
  String _chunkLine;
  size_t _chunkRemaining = 0;
};
