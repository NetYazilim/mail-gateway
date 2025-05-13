# MQTT to Email Gateway Service

This Go service acts as a bridge between an MQTT message broker and an SMTP server. It listens for messages on a specified MQTT topic, parses them as email requests, and sends emails accordingly. It features configurable rate limiting, SMTP options, and structured logging.

## Features

* **MQTT Driven:** Consumes email requests from an MQTT topic.
* **SMTP Email Sending:** Sends emails using a configurable SMTP server.
* **Flexible Configuration:** Easily configurable via environment variables or a `.env` file.
* **Rate Limiting:**
    * Supports email sending rate limits per minute (primary).
    * **Discard Behavior:** If the rate limit is exceeded, new email requests are discarded (not queued or waited upon).
* **SMTP TLS Control:** Supports `TLSMandatory`, `TLSOpportunistic`, and `NoTLS` policies for SMTP connections, along with options to skip TLS certificate verification for development/testing.
* **Input Validation:** Validates incoming MQTT message payloads and email recipient formats.
* **JSON Message Body Formatting:** Attempts to pretty-print JSON strings if provided as the message body.
* **Structured Logging:** Outputs logs in JSON format for easier parsing and analysis.
* **Graceful Shutdown:** Handles `SIGINT` and `SIGTERM` for clean shutdown.
* **MQTT Auto-Reconnect:** Automatically attempts to reconnect to the MQTT broker if the connection is lost.


## Configuration

The service is configured using environment variables. You can also place these variables in a `.env` file in the root directory of the application.

### Key Environment Variables:

**SMTP Configuration:**

* `SMTP_HOST`: (Required) Hostname or IP address of your SMTP server.
* `SMTP_PORT`: Port number for the SMTP server (default: `587`).
* `SMTP_USERNAME`: Username for SMTP authentication.
* `SMTP_PASSWORD`: Password for SMTP authentication.
* `SMTP_TLS_SKIP_VERIFY`: Set to `true` to skip TLS certificate verification (e.g., for self-signed certificates in dev). Default: `false`.
* `SMTP_FROM`: The "From" email address for outgoing emails. If not set, `SMTP_USERNAME` is used.
* `SMTP_FROM_NAME`: The display name for the "From" address (e.g., "My Application").
* `SMTP_TIMEOUT`: Timeout in seconds for SMTP connection and operations (default: `15`).
* `SMTP_TLS_POLICY`: TLS policy for SMTP. Options:
    * `TLSMandatory` (default): Always use TLS.
    * `TLSOpportunistic`: Use TLS if available (STARTTLS).
    * `NoTLS`: Do not use TLS.

**MQTT Configuration:**

* `MQTT_BROKER`: URL of the MQTT broker (default: `tcp://localhost:1883`).
* `MQTT_TOPIC`: MQTT topic to subscribe to for email requests (default: `email/send`).
* `MQTT_CLIENT_ID`: Client ID for the MQTT connection (default: `mqtt-mail-gateway`).
* `MQTT_QOS`: MQTT Quality of Service level for subscription (0, 1, or 2) (default: `1`).
* `MQTT_USERNAME`: Username for MQTT broker authentication.
* `MQTT_PASSWORD`: Password for MQTT broker authentication.

**Rate Limiting Configuration:**

* `SMTP_RATE_LIMIT_PER_MINUTE`: Maximum emails to send per minute. If this is set to a positive value, it takes precedence. If the limit is exceeded, emails are **discarded**. (Default: `0`, meaning per-second configuration is checked).
    * *Example:* `SMTP_RATE_LIMIT_PER_MINUTE=60` (allows up to 60 emails per minute, then discards further requests until capacity is available again).

## Usage

Publish a JSON message to the configured `MQTT_TOPIC` with the following structure:

```json
{
  "recipients": "user1@example.com, user2@example.com; user3@example.com",
  "subject": "Hello from MQTT!",
  "message": "This is the body of your email. It can be plain text or a JSON string to be pretty-printed."
}