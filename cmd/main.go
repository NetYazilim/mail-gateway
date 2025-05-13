package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"golang.org/x/time/rate"
	"log/slog"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/cristalhq/aconfig"
	"github.com/cristalhq/aconfig/aconfigdotenv" // Required by aconfig
	mqtt "github.com/eclipse/paho.mqtt.golang"
	gomail "github.com/wneessen/go-mail"
)

// Config holds the application configuration, loaded from environment variables.
type Config struct {
	SMTPHost               string `env:"SMTP_HOST" required:"true"`
	SMTPPort               int    `env:"SMTP_PORT" default:"587"`
	SMTPUsername           string `env:"SMTP_USERNAME"`
	SMTPPassword           string `env:"SMTP_PASSWORD"`                        // Consider using more secure secret management in production
	SMTPTLSSkipVerify      bool   `env:"SMTP_TLS_SKIP_VERIFY" default:"false"` // Set to true for self-signed certs, false for production
	SMTPFrom               string `env:"SMTP_FROM" required:"true"`
	SMTPFromName           string `env:"SMTP_FROM_NAME"`
	SMTPTimeout            int    `env:"SMTP_TIMEOUT" default:"15"`              // Timeout in seconds for SMTP connection
	SMTPTLSPolicy          string `env:"SMTP_TLS_POLICY" default:"TLSMandatory"` // TLS policy: TLSMandatory, TLSOpportunistic, NoTLS
	SMTPRateLimitPerMinute int    `env:"SMTP_RATE_LIMIT" default:"50"`           // Max emails per minute. 0 or less to use per-second config or disable.
	MQTTBroker             string `env:"MQTT_BROKER" default:"tcp://localhost:1883"`
	MQTTTopic              string `env:"MQTT_TOPIC" default:"email/send"`
	MQTTClientID           string `env:"MQTT_CLIENT_ID" default:"mqtt-mail-gateway"`
	MQTTQoS                byte   `env:"MQTT_QOS" default:"1"` // Quality of Service: 0, 1, or 2
	MQTTUsername           string `env:"MQTT_USERNAME" default:""`
	MQTTPassword           string `env:"MQTT_PASSWORD" default:""`
}

// MailRequest defines the structure of the expected JSON payload from MQTT.
type MailRequest struct {
	Recipients string `json:"recipients"`
	Subject    string `json:"subject"`
	Message    string `json:"message"` // Assuming plain text message body
}

var cfg Config
var mailClient *gomail.Client
var mqttClient mqtt.Client
var emailRateLimiter *rate.Limiter // For SMTP rate limiting
var emailRegex *regexp.Regexp
var mailErr error

// messageHandler processes incoming MQTT messages.
var messageHandler mqtt.MessageHandler = func(client mqtt.Client, msg mqtt.Message) {
	slog.Info("Received MQTT message", "topic", msg.Topic(), "payload_len", len(msg.Payload()))

	var request MailRequest
	if err := json.Unmarshal(msg.Payload(), &request); err != nil {
		slog.Error("Failed to unmarshal JSON payload", "error", err, "payload", string(msg.Payload()))
		return // Stop processing this message
	}

	// Basic validation
	if request.Recipients == "" || request.Subject == "" || request.Message == "" {
		slog.Error("Invalid mail request: missing fields", "request", request)
		return
	}

	slog.Info("Processing email request", "recipient", request.Recipients, "subject", request.Subject)

	recipients := request.Recipients
	recipients = strings.ReplaceAll(recipients, " ", "")
	recipients = strings.ReplaceAll(recipients, ",", ";")
	recipientsList := strings.Split(recipients, ";")

	validRecipients := []string{}

	for _, recipient := range recipientsList {
		if emailRegex.MatchString(recipient) {
			validRecipients = append(validRecipients, recipient)
		}
	}

	if len(validRecipients) == 0 {
		slog.Error("No valid email addresses found", "recipients", recipientsList)
		return
	}

	messageBody, err := prettyPrintJson(request.Message)
	if err != nil {
		slog.Warn("Could not pretty print message body, using as is.", "error", err)
		messageBody = request.Message
	}

	// Create email message
	m := gomail.NewMsg()
	if err := m.From(cfg.SMTPFrom); err != nil {
		slog.Error("Failed to set 'From' address", "error", err, "address", cfg.SMTPFrom)
		return
	}

	if err := m.To(validRecipients...); err != nil {
		slog.Error("Failed to set 'To' address", "error", err, "address", recipientsList)
		return
	}

	if err := m.From(cfg.SMTPFrom); err != nil {
		// From adresi genellikle kullanıcı adı ile aynıdır ancak farklı olabilir.
		slog.Error("Failed to set 'From' address", "error", err, "address", cfg.SMTPFrom)
		return
	}
	/*
		if cfg.SMTPFromName != "" {
			m.FromFormat(cfg.SMTPFromName, cfg.SMTPFrom)
		}

	*/

	m.Subject(request.Subject)
	m.SetBodyString(gomail.TypeTextPlain, messageBody) // Assuming plain text

	slog.Debug("Checking email rate limiter token...")
	if !emailRateLimiter.Allow() {

		slog.Warn("Rate limit exceeded. Email discarded.",
			"recipient", request.Recipients,
			"subject", request.Subject)
		return // Stop processing this message
	}
	slog.Debug("Rate limiter token acquired (allowed).")

	// Send the email
	// Use DialAndSend which connects, sends, and closes. Suitable if sending rate isn't extremely high.
	// For high throughput, consider keeping the connection open using mailClient.Dial() and m.Send(mailClient)
	if err := mailClient.DialAndSend(m); err != nil {
		slog.Error("Failed to send email", "error", err, "recipient", request.Recipients, "subject", request.Subject)
	} else {
		slog.Info("Email sent successfully", "recipient", request.Recipients, "subject", request.Subject)
	}
}

// onConnectHandler is executed when the MQTT client successfully connects.
var onConnectHandler mqtt.OnConnectHandler = func(client mqtt.Client) {
	slog.Info("Connected to MQTT broker", "broker", cfg.MQTTBroker)
	// Subscribe to the topic upon connection
	token := client.Subscribe(cfg.MQTTTopic, cfg.MQTTQoS, messageHandler)
	go func() {
		_ = token.Wait() // Wait for subscription confirmation
		if token.Error() != nil {
			slog.Error("Failed to subscribe to MQTT topic", "topic", cfg.MQTTTopic, "error", token.Error())
			// Maybe attempt retry or exit? For now, just log.
		} else {
			slog.Info("Successfully subscribed to MQTT topic", "topic", cfg.MQTTTopic, "qos", cfg.MQTTQoS)
		}
	}()
}

// onConnectionLostHandler is executed when the MQTT connection is lost.
var onConnectionLostHandler mqtt.ConnectionLostHandler = func(client mqtt.Client, err error) {
	slog.Error("MQTT connection lost", "error", err)
	// The Paho client library has auto-reconnect capabilities if configured.
}

func prettyPrintJson(rawJson string) (string, error) {

	var data interface{}
	err := json.Unmarshal([]byte(rawJson), &data)
	if err != nil {
		return "", fmt.Errorf("error unmarshaling JSON: %w", err)
	}

	prettyJSON, err := json.MarshalIndent(data, "", "  ") // Using two spaces for indentation
	if err != nil {
		// This error is less likely if unmarshaling succeeded, but good practice to check.
		return "", fmt.Errorf("error marshaling JSON with indent: %w", err)
	}

	// 3. Convert the resulting byte slice to a string and return it.
	return string(prettyJSON), nil
}

func main() {

	// --- Initialize Logging ---
	logHandler := slog.NewJSONHandler(os.Stderr, nil) // Use JSON structured logging
	logger := slog.New(logHandler)
	slog.SetDefault(logger)
	slog.Info("Starting MQTT Mailer Service...")

	// --- Load Configuration ---
	loader := aconfig.LoaderFor(&cfg, aconfig.Config{
		SkipFlags:          true,             // Don't use command-line flags
		EnvPrefix:          "",               // No global prefix for environment variables
		AllowUnknownFields: true,             // Allow other env vars to exist
		Files:              []string{".env"}, // No config files by default
		FileDecoders: map[string]aconfig.FileDecoder{ // Need this even if not using files

			".env": aconfigdotenv.New(),
		},
	})

	if err := loader.Load(); err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}
	slog.Info("Configuration loaded successfully",
		"mail_host", cfg.SMTPHost, "mail_port", cfg.SMTPPort, "mail_user", cfg.SMTPUsername,
		"mqtt_broker", cfg.MQTTBroker, "mqtt_topic", cfg.MQTTTopic,
		"smtp_rate_limit_per_minute", cfg.SMTPRateLimitPerMinute, // New log field
	)
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	if !emailRegex.MatchString(cfg.SMTPFrom) {
		slog.Error("SMTPFrom is invalid", "error", cfg.SMTPFrom)
		os.Exit(1)
	}

	// --- Initialize SMTP Rate Limiter ---
	if cfg.SMTPRateLimitPerMinute > 0 {
		// Calculate rate per second from per minute limit
		limitPerSecond := float64(cfg.SMTPRateLimitPerMinute) / 60.0
		// Burst will be equal to the per-minute limit, allowing the system to "catch up"
		// or send a batch up to this size if tokens have accumulated.
		burstSize := cfg.SMTPRateLimitPerMinute
		slog.Info("SMTP rate limiting enabled (per minute).",
			"limit_per_minute", cfg.SMTPRateLimitPerMinute,
			"equivalent_rate_per_second", limitPerSecond,
			"burst_allowance", burstSize)
		emailRateLimiter = rate.NewLimiter(rate.Limit(limitPerSecond), burstSize)

	} else {
		slog.Info("SMTP rate limiting is disabled (neither per-minute rate configured).")
		// rate.Inf means no limit. Burst is 1, but largely irrelevant with an infinite rate.
		emailRateLimiter = rate.NewLimiter(rate.Inf, 1)
	}
	// --- Initialize Mail Client ---

	// Assuming PLAIN auth and STARTTLS (common for port 587). Adjust if needed (e.g., SSL on 465).
	// Use gomail.WithSSL() for implicit SSL (port 465) instead of WithTLSPolicy(gomail.TLSMandatory)

	mailOpts := []gomail.Option{
		gomail.WithPort(cfg.SMTPPort),
		gomail.WithUsername(cfg.SMTPUsername),
		gomail.WithPassword(cfg.SMTPPassword),
		gomail.WithTimeout(time.Duration(cfg.SMTPTimeout) * time.Second), // Set timeout for mail client operations
	}

	var tlsPolicy gomail.TLSPolicy

	switch strings.ToLower(cfg.SMTPTLSPolicy) { // Convert to lower for case-insensitivity
	case "tlsmandatory", "mandatory":
		tlsPolicy = gomail.TLSMandatory
	case "tlsopportunistic", "opportunistic":
		tlsPolicy = gomail.TLSOpportunistic
	case "notls":
		tlsPolicy = gomail.NoTLS
	default:
		slog.Warn("Unknown SMTP TLS Policy, defaulting to TLSMandatory", "policy", cfg.SMTPTLSPolicy)
		tlsPolicy = gomail.TLSMandatory
	}
	mailOpts = append(mailOpts, gomail.WithTLSPolicy(tlsPolicy))

	if cfg.SMTPTLSSkipVerify {
		mailOpts = append(mailOpts, gomail.WithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}

	mailClient, mailErr = gomail.NewClient(cfg.SMTPHost, mailOpts...)
	if mailErr != nil {
		slog.Error("Failed to create mail client", "error", mailErr)
		os.Exit(1)
	}
	// You could optionally test the connection here using mailClient.Dial() if needed

	// --- Initialize MQTT Client ---
	opts := mqtt.NewClientOptions()
	opts.AddBroker(cfg.MQTTBroker)
	opts.SetClientID(cfg.MQTTClientID)
	opts.SetUsername(cfg.MQTTUsername)            // Add username if MQTT broker requires auth
	opts.SetPassword(cfg.MQTTPassword)            // Add password if MQTT broker requires auth
	opts.SetDefaultPublishHandler(messageHandler) // Set the default message handler
	opts.SetAutoReconnect(true)                   // Enable auto-reconnect
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(5 * time.Second)
	opts.SetMaxReconnectInterval(1 * time.Minute)
	opts.OnConnect = onConnectHandler               // Set connect handler
	opts.OnConnectionLost = onConnectionLostHandler // Set connection lost handler

	mqttClient = mqtt.NewClient(opts)
	slog.Info("Attempting to connect to MQTT broker...")
	if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
		slog.Error("Failed to connect to MQTT broker", "error", token.Error())
		os.Exit(1) // Exit if initial connection fails
	}

	// --- Wait for Shutdown Signal ---
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	slog.Info("MQTT Mailer Service is running. Waiting for messages or termination signal...")

	<-quit // Block until a signal is received

	// --- Graceful Shutdown ---
	slog.Info("Received termination signal. Shutting down...")

	// Disconnect MQTT client (give 250ms for pending operations)
	if mqttClient.IsConnected() {
		mqttClient.Disconnect(250)
		slog.Info("MQTT client disconnected.")
	} else {
		slog.Info("MQTT client was already disconnected.")
	}

	slog.Info("Shutdown complete.")
}
