#include "AsyncHttpsClient.h"
#include <time.h>

// Root CA for api.example.com
static const char ROOT_CA[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgISA5...
...snip...
-----END CERTIFICATE-----
)EOF";

AsyncHttpsClient https;

void waitForTime() {
  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");
  time_t now = 0;
  while ((now = time(nullptr)) < 1600000000) {
    delay(200);
  }
  https.setUnixTime(now);
}

void configureHttps() {
  https.setCACert(ROOT_CA);

  AsyncHttpsClient::Options opt;
  opt.timeoutMs = 20000;
  opt.maxBodyBytes = 8 * 1024;
  https.setOptions(opt);
}

void startRequest() {
  if (!https.beginGet("api.example.com", 443, "/ping")) {
    Serial.print("beginGet failed: ");
    Serial.println(https.errorMsg());
  }
}

void setup() {
  Serial.begin(115200);

  WiFi.mode(WIFI_STA);
  WiFi.begin("SSID", "PASS");
  while (WiFi.status() != WL_CONNECTED) delay(200);

  waitForTime();
  configureHttps();
  startRequest();
}

void loop() {
  https.poll();

  if (https.done()) {
    Serial.println("HTTPS OK");
    Serial.println(https.status());
    Serial.println(https.body());

    delay(5000);
    startRequest();
  }

  if (https.error()) {
    Serial.print("HTTPS ERROR: ");
    Serial.println(https.errorMsg());

    delay(3000);
    startRequest();
  }
}
