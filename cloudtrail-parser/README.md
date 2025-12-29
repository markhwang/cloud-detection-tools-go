# CloudTrail Parser

High-fidelity threat detection for AWS CloudTrail events, focusing on privilege escalation, data exfiltration, and resource deletion attacks.

## Overview

This tool parses AWS CloudTrail logs and detects high-risk security events using rule-based detection logic aligned with the MITRE ATT&CK framework.

## Detection Categories

### 1. Privilege Escalation (HIGH)
Detects IAM permission modifications that could lead to privilege escalation:
- `AttachUserPolicy`, `AttachGroupPolicy`, `AttachRolePolicy`
- `CreateAccessKey` - Potential credential creation for persistence
- `CreateUser`, `CreateRole` - New principal creation
- `PutUserPolicy`, `PutGroupPolicy`, `PutRolePolicy` - Inline policy additions
- `UpdateAssumeRolePolicy` - Role trust policy modifications

**MITRE ATT&CK**: T1098 (Account Manipulation), T1078 (Valid Accounts)

### 2. Data Exfiltration Risk (CRITICAL)
Detects S3 and database events that could enable data exfiltration:
- `PutBucketPolicy` - Bucket policy changes (potential public access)
- `DeleteBucketPublicAccessBlock` - Removing public access protections
- `PutBucketAcl` - ACL modifications allowing external access
- `CreateDBSnapshot`, `ModifyDBSnapshotAttribute` - Database snapshot sharing
- `ModifySnapshotAttribute` - EC2 snapshot sharing

**MITRE ATT&CK**: T1537 (Transfer Data to Cloud Account), T1020 (Automated Exfiltration)

### 3. Resource Deletion (HIGH)
Detects destructive actions and evidence removal:
- `DeleteBucket`, `DeleteDBInstance`, `TerminateInstances`
- `DeleteTrail`, `DeleteFlowLogs`, `DeleteLogGroup` - Logging deletion
- `DisableLogging` - CloudTrail logging disabled

**MITRE ATT&CK**: T1485 (Data Destruction), T1070 (Indicator Removal)

### 4. Suspicious Authentication (MEDIUM)
Detects authentication events requiring investigation:
- `ConsoleLogin` - AWS console access (especially failed attempts)

**MITRE ATT&CK**: T1078 (Valid Accounts), T1110 (Brute Force)

## Usage

### Quick Start
```bash
# Parse a single CloudTrail event
go run main.go --input sample_cloudtrail.json
```

### Build Executable
```bash
go build -o cloudtrail-parser
./cloudtrail-parser --input sample_cloudtrail.json
```

### Options
```
--input <file>    Path to CloudTrail JSON file (required)
--verbose         Enable verbose output
```

## Sample Output

```
⚠️  Detected 1 high-risk event(s)

================================================================================
[HIGH] Privilege Escalation ALERT
================================================================================
Timestamp:   2025-12-29T10:30:00Z
Event:       AttachUserPolicy
Description: IAM policy attached to user
User:        alice
Source IP:   203.0.113.42
Region:      us-east-1
================================================================================

Summary:
- Total Alerts: 1
- HIGH: 1
```

## Testing

### Sample CloudTrail Events
The repository includes `sample_cloudtrail.json` with a privilege escalation event (AttachUserPolicy granting AdministratorAccess).

### Create Your Own Test Events
```bash
# Privilege escalation example
cat > test_privilege_escalation.json <<EOF
{
  "eventVersion": "1.08",
  "eventTime": "2025-12-29T10:30:00Z",
  "eventName": "AttachUserPolicy",
  "eventSource": "iam.amazonaws.com",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.42",
  "userAgent": "aws-cli/2.13.0",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDACKCEVSQ6C2EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/alice",
    "accountId": "123456789012",
    "userName": "alice"
  },
  "requestParameters": {
    "userName": "bob",
    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
  }
}
EOF

go run main.go --input test_privilege_escalation.json
```

## Architecture

```
CloudTrail JSON → Parse Event → Detection Engine → Generate Alerts
                      ↓               ↓                  ↓
                 UserIdentity    Rule Matching      Alert Output
                 EventName       (4 categories)     (JSON/stdout)
                 SourceIP
```

### Detection Engine
The `DetectionEngine` struct processes events through multiple detection categories:
1. Check against privilege escalation event list
2. Check against data exfiltration event list
3. Check against resource deletion event list
4. Check against suspicious authentication event list

Each match generates an `Alert` with:
- Severity (CRITICAL, HIGH, MEDIUM)
- Category (threat type)
- Event context (timestamp, user, IP, region)
- Description

## Performance Considerations

This tool is designed for single-event analysis. For high-volume log processing:
- Use goroutines for concurrent event processing
- Implement buffered channels for event streaming
- Add batch processing capabilities

See future roadmap for streaming support.

## Future Enhancements

- [ ] Batch processing for multiple CloudTrail events
- [ ] JSON output format for SIEM integration
- [ ] Behavioral analytics (baseline deviation detection)
- [ ] Real-time streaming from CloudTrail Lake
- [ ] Integration with AWS Security Hub
- [ ] Custom detection rule support (YAML/JSON)
- [ ] GeoIP enrichment for source IP analysis
- [ ] Threat intelligence feed integration

## Detection Engineering Best Practices

This tool implements:
- **High-fidelity rules** - Focus on events with high confidence
- **Context-aware alerts** - Include user, IP, region, timestamp
- **Severity classification** - CRITICAL, HIGH, MEDIUM for prioritization
- **MITRE ATT&CK mapping** - Align detections to adversary tactics
- **Minimal false positives** - Specific event matching vs broad patterns

## Real-World Use Cases

### SOC/SIEM Integration
Integrate with Splunk, Sentinel, or Chronicle for real-time alerting:
```bash
# Process CloudTrail logs continuously
tail -f /var/log/cloudtrail/*.json | while read event; do
  echo "$event" > temp.json
  ./cloudtrail-parser --input temp.json
done
```

### Incident Response
Rapidly analyze CloudTrail logs during security incidents:
```bash
# Check for privilege escalation in last 24 hours
find /cloudtrail-logs/ -name "*.json" -mtime -1 -exec \
  ./cloudtrail-parser --input {} \;
```

### Threat Hunting
Proactive search for compromise indicators:
```bash
# Hunt for data exfiltration attempts
grep -l "PutBucketPolicy\|DeleteBucketPublicAccessBlock" *.json | \
  xargs -I {} ./cloudtrail-parser --input {}
```

## Contributing

Contributions welcome! Areas for improvement:
- Additional detection rules
- Performance optimizations
- Output format options
- Error handling enhancements

## References

- [AWS CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)

---

**Built for high-fidelity cloud threat detection**
