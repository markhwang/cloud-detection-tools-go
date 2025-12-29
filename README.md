# Cloud Detection Tools in Go

Cloud-native threat detection and security monitoring tools built in Go for AWS, Azure, and GCP.

## Overview

This repository contains production-grade detection engineering tools for cloud security monitoring, focusing on:
- **High-fidelity detection** of cloud-native threats
- **Performance** - Designed to process millions of events per second
- **Multi-cloud support** - AWS, Azure, GCP security telemetry

Built with Go for performance, concurrency, and reliability in high-volume security environments.

## Tools

### 1. CloudTrail Parser
Parses AWS CloudTrail logs and detects high-risk security events including:
- Privilege escalation (IAM policy attachments, role assumption)
- Data exfiltration (S3 bucket policy changes, public access grants)
- Resource deletion (DeleteBucket, TerminateInstances)
- Suspicious authentication (ConsoleLogin from unusual IPs)

**Status**: ✅ Complete
**Location**: [`cloudtrail-parser/`](./cloudtrail-parser)

### 2. IAM Anomaly Detector
Behavioral detection for AWS IAM threats:
- Unusual permission grants (baseline anomaly detection)
- Suspicious access key creation patterns
- Role assumption abuse detection
- Privilege escalation attempts

**Status**: 🚧 In Progress
**Location**: [`iam-anomaly-detector/`](./iam-anomaly-detector)

### 3. Detection Rule Validator
Automated testing framework for detection rules:
- Load detection rules from YAML/JSON
- Run test events against rule engine
- Generate coverage reports
- CI/CD integration for detection-as-code workflows

**Status**: 📋 Planned
**Location**: [`detection-validator/`](./detection-validator)

## Quick Start

### Prerequisites
```bash
# Install Go 1.21+
brew install go

# Verify installation
go version
```

### Run CloudTrail Parser
```bash
cd cloudtrail-parser
go run main.go --input sample_cloudtrail.json
```

## Architecture

Each tool follows a similar architecture:
1. **Event Ingestion** - Parse JSON/log formats (CloudTrail, GuardDuty, etc.)
2. **Detection Logic** - Rule-based and anomaly detection engines
3. **Alert Generation** - Structured alert output with severity, context
4. **Performance** - Concurrent processing using goroutines

## Detection Engineering Philosophy

These tools implement detection engineering best practices:
- **High fidelity** - Focus on reducing false positives through context
- **MITRE ATT&CK alignment** - Map detections to adversary TTPs
- **Performance at scale** - Handle billions of events per day
- **Detection-as-Code** - Version-controlled, testable, CI/CD integrated

## Use Cases

- **SOC/SIEM Integration** - Feed detections into Splunk, Sentinel, Chronicle
- **Incident Response** - Rapid cloud log analysis during investigations
- **Threat Hunting** - Proactive search for cloud-native threats
- **Red Team Detection** - Validate security controls against cloud attacks

## Development

### Project Structure
```
cloud-detection-tools-go/
├── cloudtrail-parser/       # AWS CloudTrail threat detection
├── iam-anomaly-detector/    # IAM behavioral analytics
├── detection-validator/     # Detection rule testing framework
├── docs/                    # Architecture and design docs
└── README.md
```

### Building
```bash
# Build all tools
make build

# Run tests
make test

# Run linter
make lint
```

## Roadmap

- [x] CloudTrail high-risk event detection
- [ ] IAM anomaly detection with baseline tracking
- [ ] Detection rule validator and testing framework
- [ ] Azure Activity Log parser
- [ ] GCP Cloud Audit Log parser
- [ ] Multi-cloud detection correlation
- [ ] Real-time streaming support (Kafka, Kinesis)

## Author

**Mark Hwang**
Principal Detection Engineer | Cloud Security Specialist

- 15+ years in cybersecurity and detection engineering
- Built 200+ production detection rules with MITRE ATT&CK alignment
- Multi-cloud telemetry pipeline architecture (AWS, Azure, GCP)
- Detection-as-Code pioneer in financial services

## License

MIT License - See [LICENSE](LICENSE) for details

## Related Projects

- [Falco](https://github.com/falcosecurity/falco) - Cloud-native runtime security
- [CloudQuery](https://github.com/cloudquery/cloudquery) - Cloud asset inventory
- [StreamAlert](https://github.com/airbnb/streamalert) - Serverless real-time detection

---

**Built for high-performance cloud threat detection at scale**
