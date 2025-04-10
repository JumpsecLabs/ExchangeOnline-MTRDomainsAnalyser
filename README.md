# ExchangeOnline-MTR_Domains - Exchange Online Mail Transport Rules' Domain/IP Categorisation
A PowerShell script that analyses approved and rejected domains specified via Mail Transport Rules in Exchange Online, leveraging the ExchangeOnline PowerShell Module.

## Overview
This PowerShell script analyses Exchange Online Mail Transport Rules (MTRs) to systematically categorise domains and IP addresses into Approved, Rejected, or Uncategorised groups based on rule configurations. It enhances your email security posture by clearly identifying allowed and blocked domains/IPs, assisting in building robust allow and deny lists for your tenant.

This script is designed to be used independently or alongside [JumpsecLabs' MTR-Analyser](https://github.com/JumpsecLabs/MTR-Analyser), enriching your existing auditing capabilities with detailed categorisation and conflict identification.

## Key Features

- **Approved and Rejected Domains/IPs**: Automatically classifies domains/IPs based on explicit conditions defined within your Exchange Online Transport Rules.
- **Conflict Detection**: Identifies domains/IPs appearing in both approved and rejected lists, marking them as excluded to avoid misconfiguration and potential security gaps.
- **Uncategorised Rules Analysis**: Highlights rules that don't clearly fit into approval or rejection categories, providing detailed insights to facilitate manual review.
- **Domain/IP Lookup Feature**: Quickly look up a specific domain or IP address to identify associated rules and their classification, streamlining incident response and rule audits.
- **Detailed Conflict Reports**: Provides comprehensive information about conflicting rules when the `-ShowConflicts` flag is used, ensuring precise issue resolution.

## Benefits
- Enhances clarity and accuracy in managing Exchange Online Transport Rules.
- Helps improving the security and integrity of email flows by identifying allowed and disallowed senders.
- Reduces administrative overhead by automating the classification and detection of conflicts.
- Facilitates proactive security by clearly defining tenant-wide allow/deny lists.

## Usage
```powershell
.\ExchangeOnline-MTR_Domains.ps1 [-oA approved.txt] [-oR rejected.txt] [-oU uncategorised.csv] [-oE excluded.txt] [-Lookup domainname.com] [-ShowConflicts] [-Help] [-Verbose]
```

### Parameters
- `-oA`: Specifies output file for approved domains/IPs.
- `-oR`: Specifies output file for rejected domains/IPs.
- `-oU`: Specifies output CSV file for uncategorised rules.
- `-oE`: Specifies output file for excluded (conflicting) domains/IPs.
- `-Lookup`: Looks up a specific domain/IP, detailing associated rules.
- `-ShowConflicts`: Outputs detailed conflict information.
- `-Help`: Displays usage and parameter information.
- `-Verbose`: Shows additional details during categorisation.

### Example
To categorise rules and output results:
```powershell
.\ExchangeOnline-MTR_Domains.ps1 -oA approved.txt -oR rejected.txt -oU uncategorised.csv -oE excluded.txt
```

To look up a specific domain:
```powershell
.\ExchangeOnline-MTR_Domains.ps1 -Lookup example.com
```

To show detailed conflict information:
```powershell
.\ExchangeOnline-MTR_Domains.ps1 -ShowConflicts
```

## Integration
This script complements [JumpsecLabs' MTR-Analyser](https://github.com/JumpsecLabs/MTR-Analyser), which focuses on broader MTR audit capabilities. Integrating both tools can help you have better visibility into Exchange Mail Transport Rules and enhance your overall email security analysis.

## Output Interpretation
- **Approved Domains/IPs**: Domains or IPs explicitly trusted to bypass standard security filters.
- **Rejected Domains/IPs**: Domains or IPs explicitly marked to be blocked or quarantined.
- **Uncategorised Rules**: Rules requiring manual review to determine their intent clearly.
- **Excluded Domains/IPs (Conflicts)**: Domains/IPs appearing in both approved and rejected lists, highlighting configuration issues.

## Recommendations
Run this script to check maintain an up-to-date categorisation of domains/IPs, preventing rule misconfigurations and ensuring optimal email security management.

---

### Author

Made by Fr4n 
@JUMPSEC

