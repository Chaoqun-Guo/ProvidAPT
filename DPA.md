# ProvidAPT - Data Processing Agreement

**Version 1.0 - Effective 2026-06-07**

## 1. Parties and Scope

This DPA forms part of the agreement between ProvidAPT (the "Data Processor")
and the Customer (the "Data Controller") for the processing of personal data
through the use of the ProvidAPT Software.

## 2. Processing Details

- **Purpose**: eBPF-based system event capture, provenance graph construction,
  and threat detection
- **Data Categories**: Process metadata (PID, comm, command line), file paths,
  network connections (IP addresses, ports), kernel events
- **Data Subjects**: End users of systems monitored by ProvidAPT
- **Processing Duration**: Duration of the subscription term

## 3. Data Protection

The Processor shall:
- Process data only on documented instructions from the Controller
- Implement appropriate technical measures (encryption at rest, TLS in transit,
  HMAC anonymization for PII fields)
- Ensure personnel authorized to process data are bound by confidentiality
- Notify the Controller of any data breach within 48 hours

## 4. Sub-processors

Current sub-processors:
- GitHub, Inc. (source code hosting)
- Docker, Inc. (container image distribution)

The Processor will notify the Controller of any sub-processor changes.

## 5. Data Subject Rights

The Processor shall assist the Controller in fulfilling data subject access
requests, including the right to access, rectify, or delete personal data.

## 6. Data Deletion

Upon termination, the Controller may request deletion of all processed data.
ProvidAPT provides purge tools (`providaptctl -purge`) for this purpose.

## 7. Governing Law

This DPA shall be governed by applicable data protection law, including the
GDPR (EU) 2016/679 where applicable.

---

**Contact**: dpo@providapt.io
