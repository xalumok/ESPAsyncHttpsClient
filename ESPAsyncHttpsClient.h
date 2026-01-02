#pragma once

#if defined(ESP8266)
  #include <ESP8266WiFi.h>
  #include <WiFiClientSecureBearSSL.h>
  using SecureClientT = BearSSL::WiFiClientSecure;
#elif defined(ESP32)
  #include <WiFi.h>
  #include <WiFiClientSecure.h>
  using SecureClientT = WiFiClientSecure;
#else
  #error "This class supports only ESP8266 or ESP32"
#endif

class ESPAsyncHttpsClient {
public:
  enum Method { M_GET, M_POST };
  enum State  { IDLE, CONNECT, SEND, READ_HEADERS, READ_BODY, DONE, ERROR };

  // --- Config ---
  void setTimeoutMs(uint32_t t) { _timeoutMs = t; }

  // Insecure TLS (fast to test; NOT recommended for production)
  void setInsecureTLS(bool on) {
    _useInsecure = on;
    _hasCACert = false;
    _caPem = nullptr;
  }

  // ESP32: validate using CA cert PEM. (ESP8266: ignored by default in this minimal version)
  // You can still call it on ESP8266; it just won't apply unless you extend it with trust anchors.
  void setCACert(const char* caPem) {
    _caPem = caPem;
    _hasCACert = (caPem && caPem[0]);
    _useInsecure = !_hasCACert;
  }

  // --- Start requests ---
  void beginGet(const String& host, uint16_t port, const String& path) {
    beginRequest(M_GET, host, port, path, "", "");
  }

  void beginPost(const String& host, uint16_t port, const String& path,
                 const String& body, const String& contentType = "application/json") {
    beginRequest(M_POST, host, port, path, body, contentType);
  }

  // --- Pump state machine ---
  void poll() {
    if (_state == IDLE || _state == DONE || _state == ERROR) return;

    // Keep WiFi stack happy
#if defined(ESP8266)
    yield();
#else
    delay(0);
#endif

    if (millis() - _startMs > _timeoutMs) {
      fail("timeout");
      return;
    }

    switch (_state) {
      case CONNECT: {
        if (!_client.connected()) {
          if (!_client.connect(_host.c_str(), _port)) {
            fail("connect failed");
            return;
          }
        }
        _state = SEND;
      } break;

      case SEND: {
        size_t written = _client.print(_request);
        if (written == 0) {
          fail("send failed");
          return;
        }
        _state = READ_HEADERS;
      } break;

      case READ_HEADERS: {
        while (_client.available()) {
          String line = _client.readStringUntil('\n');
          line.trim(); // removes \r too

          if (line.startsWith("HTTP/1.1") && line.length() >= 12) {
            _status = line.substring(9, 12).toInt();
          } else if (line.startsWith("HTTP/2")) {
            int sp = line.indexOf(' ');
            if (sp > 0 && line.length() >= sp + 4) _status = line.substring(sp + 1, sp + 4).toInt();
          }

          if (line.length() == 0) { // end of headers
            _state = READ_BODY;
            return;
          }
        }

        if (!_client.connected() && !_client.available()) {
          fail("closed during headers");
          return;
        }
      } break;

      case READ_BODY: {
        while (_client.available()) {
          uint8_t buf[512];
#if defined(ESP8266)
          int n = _client.readBytes((char*)buf, sizeof(buf));
#else
          int n = _client.read(buf, sizeof(buf));
#endif
          if (n > 0) onBodyChunk(buf, (size_t)n);
        }

        if (!_client.connected() && !_client.available()) {
          _client.stop();
          _state = DONE;
        }
      } break;

      default:
        break;
    }
  }

  // --- Results / status ---
  bool done()  const { return _state == DONE; }
  bool error() const { return _state == ERROR; }
  State state() const { return _state; }

  int status() const { return _status; }
  const String& errorMsg() const { return _err; }
  String body() const { return _body; }

  void reset() {
    _client.stop();
    _state = IDLE;
    _status = -1;
    _err = "";
    _body = "";
    _request = "";
    _startMs = 0;
  }

  // Override to stream instead of buffering (recommended for larger responses)
  virtual void onBodyChunk(const uint8_t* data, size_t len) {
    _body.reserve(_body.length() + len);
    for (size_t i = 0; i < len; i++) _body += (char)data[i];
  }

private:
  void beginRequest(Method m, const String& host, uint16_t port,
                    const String& path, const String& body,
                    const String& contentType) {
    reset();

    _method = m;
    _host = host;
    _port = port;
    _path = path;

    // TLS config
#if defined(ESP8266)
    // Minimal: insecure by default (or keep it insecure even if CA provided).
    // You can extend with BearSSL trust anchors if you want real validation.
    if (_useInsecure) _client.setInsecure();
    else _client.setInsecure(); // intentionally: keep simple/compatible
#else
    if (_useInsecure) _client.setInsecure();
    else if (_hasCACert) _client.setCACert(_caPem);
    else _client.setInsecure();
#endif

    // Build request
    _request =
      String(m == M_GET ? "GET " : "POST ") + _path + " HTTP/1.1\r\n" +
      "Host: " + _host + "\r\n" +
      "User-Agent: esp\r\n" +
      "Accept: */*\r\n" +
      "Connection: close\r\n";

    if (m == M_POST) {
      _request +=
        "Content-Type: " + contentType + "\r\n" +
        "Content-Length: " + String(body.length()) + "\r\n\r\n" +
        body;
    } else {
      _request += "\r\n";
    }

    _startMs = millis();
    _state = CONNECT;
  }

  void fail(const String& msg) {
    _err = msg;
    _state = ERROR;
    _client.stop();
  }

  SecureClientT _client;

  Method _method = M_GET;
  State  _state  = IDLE;

  String _host, _path;
  uint16_t _port = 443;

  String _request;
  String _body;
  String _err;

  int _status = -1;
  uint32_t _startMs = 0;
  uint32_t _timeoutMs = 15000;

  bool _useInsecure = true;
  bool _hasCACert = false;
  const char* _caPem = nullptr;
};
