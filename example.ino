#include "ESPAsyncHttpsClient.h"

// Root CA for api.example.com
static const char ROOT_CA[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgISA5...
...snip...
-----END CERTIFICATE-----
)EOF";


ESPAsyncHttpsClient https;

void setup() {
  Serial.begin(115200);

  WiFi.mode(WIFI_STA);
  WiFi.begin("SSID", "PASS");
  while (WiFi.status() != WL_CONNECTED) delay(200);

  // 🔐 Enable proper TLS validation
  https.setCACert(ROOT_CA);

  // HTTPS GET
  https.beginGet("api.example.com", 443, "/ping");
}

void loop() {
  https.poll();

  if (https.done()) {
    Serial.println("TLS OK");
    Serial.println(https.status());
    Serial.println(https.body());

    delay(5000);
    https.beginGet("api.example.com", 443, "/ping");
  }

  if (https.error()) {
    Serial.print("TLS ERROR: ");
    Serial.println(https.errorMsg());

    delay(3000);
    https.beginGet("api.example.com", 443, "/ping");
  }
}
