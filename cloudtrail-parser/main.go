package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"
)

// CloudTrailEvent represents a parsed AWS CloudTrail event
type CloudTrailEvent struct {
	EventVersion string    `json:"eventVersion"`
	EventTime    string    `json:"eventTime"`
	EventName    string    `json:"eventName"`
	EventSource  string    `json:"eventSource"`
	AWSRegion    string    `json:"awsRegion"`
	SourceIPAddress string `json:"sourceIPAddress"`
	UserAgent    string    `json:"userAgent"`
	UserIdentity UserIdentity `json:"userIdentity"`
	RequestParameters json.RawMessage `json:"requestParameters"`
	ResponseElements  json.RawMessage `json:"responseElements"`
	ErrorCode    string    `json:"errorCode"`
	ErrorMessage string    `json:"errorMessage"`
}

// UserIdentity contains information about the AWS principal
type UserIdentity struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
	ARN         string `json:"arn"`
	AccountID   string `json:"accountId"`
	UserName    string `json:"userName"`
}

// Alert represents a security detection alert
type Alert struct {
	Timestamp   string
	Severity    string
	Category    string
	EventName   string
	Description string
	User        string
	SourceIP    string
	Region      string
	RawEvent    CloudTrailEvent
}

// High-risk CloudTrail events categorized by threat type
var (
	privilegeEscalationEvents = map[string]string{
		"AttachUserPolicy":       "IAM policy attached to user",
		"AttachGroupPolicy":      "IAM policy attached to group",
		"AttachRolePolicy":       "IAM policy attached to role",
		"CreateAccessKey":        "IAM access key created",
		"CreateUser":             "IAM user created",
		"CreateRole":             "IAM role created",
		"PutUserPolicy":          "Inline policy added to user",
		"PutGroupPolicy":         "Inline policy added to group",
		"PutRolePolicy":          "Inline policy added to role",
		"UpdateAssumeRolePolicy": "Role trust policy modified",
	}

	dataExfiltrationEvents = map[string]string{
		"PutBucketPolicy":             "S3 bucket policy modified",
		"DeleteBucketPublicAccessBlock": "S3 public access block removed",
		"PutBucketAcl":                "S3 bucket ACL modified",
		"CreateDBSnapshot":            "Database snapshot created",
		"ModifyDBSnapshotAttribute":   "Database snapshot shared",
		"ModifySnapshotAttribute":     "EC2 snapshot shared",
	}

	resourceDeletionEvents = map[string]string{
		"DeleteBucket":           "S3 bucket deleted",
		"DeleteDBInstance":       "RDS database deleted",
		"TerminateInstances":     "EC2 instances terminated",
		"DeleteTrail":            "CloudTrail trail deleted",
		"DeleteFlowLogs":         "VPC flow logs deleted",
		"DeleteLogGroup":         "CloudWatch log group deleted",
		"DisableLogging":         "CloudTrail logging disabled",
	}

	suspiciousAuthEvents = map[string]string{
		"ConsoleLogin": "AWS console login detected",
	}
)

// DetectionEngine processes CloudTrail events and generates alerts
type DetectionEngine struct {
	verbose bool
}

// NewDetectionEngine creates a new detection engine
func NewDetectionEngine(verbose bool) *DetectionEngine {
	return &DetectionEngine{verbose: verbose}
}

// Detect runs all detection rules against an event
func (de *DetectionEngine) Detect(event CloudTrailEvent) []Alert {
	var alerts []Alert

	// Check privilege escalation
	if desc, found := privilegeEscalationEvents[event.EventName]; found {
		alerts = append(alerts, Alert{
			Timestamp:   event.EventTime,
			Severity:    "HIGH",
			Category:    "Privilege Escalation",
			EventName:   event.EventName,
			Description: desc,
			User:        de.getUserIdentifier(event.UserIdentity),
			SourceIP:    event.SourceIPAddress,
			Region:      event.AWSRegion,
			RawEvent:    event,
		})
	}

	// Check data exfiltration
	if desc, found := dataExfiltrationEvents[event.EventName]; found {
		alerts = append(alerts, Alert{
			Timestamp:   event.EventTime,
			Severity:    "CRITICAL",
			Category:    "Data Exfiltration Risk",
			EventName:   event.EventName,
			Description: desc,
			User:        de.getUserIdentifier(event.UserIdentity),
			SourceIP:    event.SourceIPAddress,
			Region:      event.AWSRegion,
			RawEvent:    event,
		})
	}

	// Check resource deletion
	if desc, found := resourceDeletionEvents[event.EventName]; found {
		alerts = append(alerts, Alert{
			Timestamp:   event.EventTime,
			Severity:    "HIGH",
			Category:    "Resource Deletion",
			EventName:   event.EventName,
			Description: desc,
			User:        de.getUserIdentifier(event.UserIdentity),
			SourceIP:    event.SourceIPAddress,
			Region:      event.AWSRegion,
			RawEvent:    event,
		})
	}

	// Check suspicious authentication
	if desc, found := suspiciousAuthEvents[event.EventName]; found {
		// Add additional context for console logins
		if event.ErrorCode != "" {
			desc = fmt.Sprintf("%s (FAILED: %s)", desc, event.ErrorCode)
		}
		alerts = append(alerts, Alert{
			Timestamp:   event.EventTime,
			Severity:    "MEDIUM",
			Category:    "Suspicious Authentication",
			EventName:   event.EventName,
			Description: desc,
			User:        de.getUserIdentifier(event.UserIdentity),
			SourceIP:    event.SourceIPAddress,
			Region:      event.AWSRegion,
			RawEvent:    event,
		})
	}

	return alerts
}

// getUserIdentifier extracts a human-readable user identifier
func (de *DetectionEngine) getUserIdentifier(identity UserIdentity) string {
	if identity.UserName != "" {
		return identity.UserName
	}
	if identity.ARN != "" {
		return identity.ARN
	}
	return identity.PrincipalID
}

// PrintAlert outputs an alert to stdout
func PrintAlert(alert Alert) {
	fmt.Println("================================================================================")
	fmt.Printf("[%s] %s ALERT\n", alert.Severity, alert.Category)
	fmt.Println("================================================================================")
	fmt.Printf("Timestamp:   %s\n", alert.Timestamp)
	fmt.Printf("Event:       %s\n", alert.EventName)
	fmt.Printf("Description: %s\n", alert.Description)
	fmt.Printf("User:        %s\n", alert.User)
	fmt.Printf("Source IP:   %s\n", alert.SourceIP)
	fmt.Printf("Region:      %s\n", alert.Region)
	fmt.Println("================================================================================")
	fmt.Println()
}

func main() {
	// Command-line flags
	inputFile := flag.String("input", "", "Path to CloudTrail JSON file")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	flag.Parse()

	if *inputFile == "" {
		fmt.Println("CloudTrail Parser - High-Risk Event Detector")
		fmt.Println("Usage: cloudtrail-parser --input <cloudtrail.json>")
		fmt.Println()
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Read CloudTrail JSON file
	data, err := ioutil.ReadFile(*inputFile)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Parse CloudTrail event
	var event CloudTrailEvent
	if err := json.Unmarshal(data, &event); err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}

	// Initialize detection engine
	engine := NewDetectionEngine(*verbose)

	// Run detections
	alerts := engine.Detect(event)

	// Output results
	if len(alerts) == 0 {
		fmt.Println("✓ No high-risk events detected")
		return
	}

	fmt.Printf("⚠️  Detected %d high-risk event(s)\n\n", len(alerts))
	for _, alert := range alerts {
		PrintAlert(alert)
	}

	// Output summary statistics
	fmt.Println("Summary:")
	fmt.Printf("- Total Alerts: %d\n", len(alerts))
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	for _, alert := range alerts {
		switch alert.Severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		}
	}
	if criticalCount > 0 {
		fmt.Printf("- CRITICAL: %d\n", criticalCount)
	}
	if highCount > 0 {
		fmt.Printf("- HIGH: %d\n", highCount)
	}
	if mediumCount > 0 {
		fmt.Printf("- MEDIUM: %d\n", mediumCount)
	}
}
