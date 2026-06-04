# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-05-15

### Added
- Initial lab setup with Active Directory Domain Controller
- Golden Ticket attack simulation using Mimikatz
- Security monitoring configuration (Security Onion, Sysmon)
- Detection rules for Kerberos ticket anomalies
- Investigation playbook for Golden Ticket incidents
- Screenshot documentation of attack and detection

### Changed
- Improved detection rule thresholds based on testing
- Enhanced investigation steps based on real-world scenarios
- Updated documentation with lessons learned

### Fixed
- Resolved false positives in detection rules
- Fixed timestamp inconsistencies in log collection

## [0.1.0] - 2024-04-10

### Added
- Basic lab environment setup
- Initial detection rule framework
- Project documentation structure