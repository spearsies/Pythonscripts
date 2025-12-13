# Threat Intelligence Aggregator

**Author:** cyb3rlop3
**Purpose:** Automated aggregation of threat intelligence from multiple security feeds for SOC analysts and security researchers

## Overview

The Threat Intelligence Aggregator is a Python-based tool that automatically collects, normalizes, and consolidates threat intelligence from multiple public security feeds. Instead of manually checking dozens of websites and feeds, this tool aggregates all critical threat intelligence into a single, searchable dataset.

## Features

### Multi-Source Aggregation
- **The Hacker News** - Latest cybersecurity news and threats
- **CISA Advisories** - Government cybersecurity alerts and advisories
- **CISA KEV** - Known Exploited Vulnerabilities catalog
- **SANS Internet Storm Center** - Real-time threat intelligence
- **US-CERT ICS** - Industrial Control Systems advisories
- **OpenPhish** - Active phishing URLs
- **Support for API-based feeds** (requires API keys)

### Data Processing
- **Automatic CVE extraction** - Identifies CVE IDs in all content
- **Deduplication** - Removes duplicate entries across sources
- **Keyword filtering** - Filter by specific threats (ransomware, malware, etc.)
- **Normalization** - Standardized data format across all sources

### Export Formats
- **JSON** - Machine-readable format for SIEM integration
- **CSV** - Spreadsheet-compatible for analysis
- **HTML** - Human-readable dashboard with statistics

### Intelligence Features
- CVE ID tracking and extraction
- Threat categorization
- Severity classification
- Indicator of Compromise (IOC) extraction
- Source attribution
- Publication date tracking

## Installation

### Requirements
- Python 3.7 or higher
- Internet connection
- No external dependencies (uses standard library only)

### Setup
```bash
# Clone or download the repository
git clone https://github.com/spearsies/Pythonscripts.git
cd Pythonscripts

# No pip install needed - uses Python standard library
```

## Quick Start

### Basic Usage

```python
from threat_intel_aggregator import ThreatIntelAggregator

# Create aggregator instance
aggregator = ThreatIntelAggregator()

# Scrape all configured sources
results = aggregator.scrape_all(items_per_source=20)

# Remove duplicates
aggregator.deduplicate()

# Export to multiple formats
aggregator.export_json('threat_intel.json')
aggregator.export_csv('threat_intel.csv')
aggregator.export_html('threat_intel.html')

# Print summary
aggregator.print_summary()
```

### Command Line Usage

```bash
# Run the default aggregator
python threat_intel_aggregator.py

# This will:
# - Scrape all configured threat intelligence sources
# - Collect ~15 items per source
# - Generate timestamped reports in JSON, CSV, and HTML formats
```

## Usage Examples

### Example 1: Daily Threat Intelligence Brief

```python
from threat_intel_aggregator import ThreatIntelAggregator
from datetime import datetime

# Create aggregator
aggregator = ThreatIntelAggregator()

# Collect intelligence
results = aggregator.scrape_all(items_per_source=30)
aggregator.deduplicate()

# Generate daily report
date_str = datetime.now().strftime('%Y-%m-%d')
aggregator.export_html(f'daily_threat_brief_{date_str}.html')
aggregator.export_json(f'daily_threat_brief_{date_str}.json')

print(f"Daily brief generated with {len(results)} threat intelligence items")
```

### Example 2: CVE-Focused Intelligence

```python
from threat_intel_aggregator import ThreatIntelAggregator

aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=25)

# Filter for items with CVEs only
cve_items = aggregator.filter_by_cve()

print(f"Found {len(cve_items)} items with CVE IDs")

# Export CVE-focused report
aggregator.results = cve_items
aggregator.export_csv('cve_threats.csv')

# Show all unique CVEs
all_cves = set()
for item in cve_items:
    all_cves.update(item.cve_ids)

print(f"Unique CVEs tracked: {len(all_cves)}")
for cve in sorted(all_cves):
    print(f"  - {cve}")
```

### Example 3: Keyword-Based Threat Hunting

```python
from threat_intel_aggregator import ThreatIntelAggregator

aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=20)

# Hunt for specific threats
keywords = ['ransomware', 'apt', 'zero-day', 'backdoor', 'supply chain']
filtered = aggregator.filter_by_keywords(keywords)

print(f"Found {len(filtered)} items matching threat keywords")

# Export filtered results
aggregator.results = filtered
aggregator.export_html('priority_threats.html')

# Display top threats
for item in filtered[:10]:
    print(f"\n[{item.source}] {item.title}")
    print(f"Category: {item.category}")
    print(f"URL: {item.url}")
    if item.cve_ids:
        print(f"CVEs: {', '.join(item.cve_ids)}")
```

### Example 4: Automated Morning Briefing

```python
from threat_intel_aggregator import ThreatIntelAggregator
import schedule
import time

def morning_briefing():
    """Generate morning threat intelligence briefing"""
    aggregator = ThreatIntelAggregator()

    print("Starting morning threat intelligence collection...")
    results = aggregator.scrape_all(items_per_source=15)
    aggregator.deduplicate()

    # Focus on high-priority items
    priority_keywords = ['critical', 'emergency', 'zero-day', 'ransomware', 'apt']
    priority_items = aggregator.filter_by_keywords(priority_keywords)

    # Generate reports
    aggregator.export_html('morning_briefing.html')

    # If priority items found, generate separate report
    if priority_items:
        aggregator.results = priority_items
        aggregator.export_html('high_priority_threats.html')
        print(f"⚠️  {len(priority_items)} high-priority threats identified!")

    aggregator.print_summary()

# Schedule for 7 AM daily
schedule.every().day.at("07:00").do(morning_briefing)

# Or run immediately
morning_briefing()
```

### Example 5: SIEM Integration (JSON Export)

```python
from threat_intel_aggregator import ThreatIntelAggregator
import json

aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=50)
aggregator.deduplicate()

# Export for SIEM ingestion
aggregator.export_json('siem_threat_feed.json')

# Read and format for specific SIEM
with open('siem_threat_feed.json', 'r') as f:
    data = json.load(f)

# Example: Extract just the IOCs for firewall rules
iocs = []
for item in data['threat_intelligence']:
    if item['indicators']:
        iocs.extend(item['indicators'])

print(f"Extracted {len(set(iocs))} unique indicators of compromise")

# Write IOC list for import
with open('ioc_list.txt', 'w') as f:
    for ioc in sorted(set(iocs)):
        f.write(f"{ioc}\n")
```

### Example 6: Specific Source Scraping

```python
from threat_intel_aggregator import ThreatIntelAggregator

aggregator = ThreatIntelAggregator()

# Scrape only CISA sources
cisa_advisories = aggregator.scrape_cisa_advisories(limit=50)
cisa_kev = aggregator.scrape_cisa_kev(limit=100)

# Combine CISA intelligence
aggregator.results = cisa_advisories + cisa_kev

print(f"Collected {len(aggregator.results)} items from CISA sources")

# Export government intelligence
aggregator.export_html('cisa_intelligence.html')
aggregator.export_json('cisa_intelligence.json')
```

## Real-World Use Cases

### For SOC Analysts

**Morning Threat Brief**
```bash
# Run daily at 7 AM to get overnight threats
python threat_intel_aggregator.py
# Review the HTML dashboard for trending threats
```

**Incident Response**
```python
# During an incident, quickly gather related intelligence
aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=30)

# Filter for incident-related keywords
incident_keywords = ['ransomware', 'lockbit', 'phishing']
related = aggregator.filter_by_keywords(incident_keywords)

# Export for incident documentation
aggregator.results = related
aggregator.export_html('incident_threat_intel.html')
```

### For Threat Intelligence Analysts

**Weekly Intelligence Report**
```python
# Collect comprehensive weekly intelligence
aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=100)
aggregator.deduplicate()

# Generate detailed report
aggregator.export_html('weekly_intel_report.html')
aggregator.export_csv('weekly_intel_data.csv')

# Extract all CVEs for vulnerability management
cve_items = aggregator.filter_by_cve()
print(f"This week's CVEs: {len(cve_items)}")
```

### For Security Researchers

**Trend Analysis**
```python
# Collect data over time for trend analysis
import os
from datetime import datetime

aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=50)

# Save with timestamp for historical analysis
timestamp = datetime.now().strftime('%Y%m%d')
aggregator.export_json(f'data/threat_intel_{timestamp}.json')

# Analyze collected data for trends
# (This data can be loaded into pandas, elasticsearch, etc.)
```

### For Compliance Teams

**Regulatory Reporting**
```python
# Collect threat intelligence for compliance reports
aggregator = ThreatIntelAggregator()
results = aggregator.scrape_all(items_per_source=50)

# Focus on government sources (CISA, US-CERT)
gov_sources = [item for item in aggregator.results
               if item.source in ['CISA', 'US-CERT ICS', 'CISA KEV']]

aggregator.results = gov_sources
aggregator.export_csv('compliance_threat_report.csv')
```

## Advanced Features

### Custom Rate Limiting

```python
aggregator = ThreatIntelAggregator(timeout=60)  # Increase timeout for slow connections
```

### Custom User Agent

```python
aggregator = ThreatIntelAggregator(
    user_agent="MyOrg SOC ThreatIntel Bot/1.0 (security@myorg.com)"
)
```

### Filtering and Analysis

```python
# Filter by multiple criteria
results = aggregator.scrape_all()

# Get high-severity items
high_severity = [item for item in results if item.severity == "High"]

# Get items from last 24 hours
from datetime import datetime, timedelta
recent = [item for item in results
          if datetime.fromisoformat(item.published_date) > datetime.now() - timedelta(days=1)]

# Get phishing-related threats
phishing = aggregator.filter_by_keywords(['phishing', 'spoofing', 'email'])
```

## API-Based Sources

Some threat intelligence sources require API keys for full access. To use them:

### AlienVault OTX
1. Sign up at https://otx.alienvault.com/
2. Get your API key from account settings
3. Add to your code:
```python
# Future enhancement - API key support
aggregator.set_api_key('otx', 'your-api-key-here')
```

### GreyNoise
1. Sign up at https://www.greynoise.io/
2. Get API key
3. Use their Python library or API

### abuse.ch URLhaus
1. Visit https://urlhaus.abuse.ch/api/
2. No API key required for basic access
3. Rate limits apply

## Output Formats

### JSON Format
```json
{
  "metadata": {
    "generated_at": "2025-12-12T10:30:00",
    "total_items": 150,
    "statistics": {
      "sources_scraped": 6,
      "items_collected": 150,
      "errors": 0
    }
  },
  "threat_intelligence": [
    {
      "title": "Critical Zero-Day in Popular Software",
      "url": "https://example.com/article",
      "source": "The Hacker News",
      "published_date": "2025-12-12",
      "category": "Vulnerability",
      "description": "Details about the vulnerability...",
      "severity": "High",
      "cve_ids": ["CVE-2025-12345"],
      "indicators": ["malicious-domain.com"]
    }
  ]
}
```

### CSV Format
```csv
title,url,source,published_date,category,description,severity,cve_ids
Critical Zero-Day,https://example.com,The Hacker News,2025-12-12,Vulnerability,Details...,High,CVE-2025-12345
```

### HTML Format
Interactive dashboard with:
- Summary statistics
- Color-coded severity
- CVE badges
- Source and category tags
- Clickable links
- Professional styling

## Performance

- **Average scrape time**: 30-60 seconds for all sources
- **Items collected**: 100-200 per run (configurable)
- **Memory usage**: ~50-100MB
- **Rate limiting**: 1-second delay between sources
- **Timeout**: 30 seconds per source (configurable)

## Troubleshooting

### Connection Errors
```python
# Increase timeout for slow connections
aggregator = ThreatIntelAggregator(timeout=60)
```

### Rate Limiting
```python
# Add delays between scrapes
import time
time.sleep(5)  # Wait 5 seconds between operations
```

### SSL Errors
```python
# Some feeds may have SSL certificate issues
# The tool handles common SSL issues gracefully
```

### Empty Results
- Check internet connection
- Verify feed URLs are still active
- Some feeds require API keys
- Rate limiting may block requests

## Security Considerations

### Safe to Use
- This tool only reads public threat intelligence
- No authentication required for public feeds
- Does not modify any systems
- Ethical use for defensive security only

### Best Practices
- Use for authorized security operations only
- Respect rate limits of public feeds
- Consider API access for high-volume needs
- Store reports securely (may contain sensitive threat data)
- Review and validate intelligence before acting

## Integration with Other Tools

### Splunk Integration
```python
# Export JSON for Splunk ingestion
aggregator.export_json('/var/log/threat_intel/feed.json')
# Configure Splunk to monitor this directory
```

### ELK Stack Integration
```python
# Format for Elasticsearch
import json
from elasticsearch import Elasticsearch

es = Elasticsearch(['localhost:9200'])
with open('threat_intel.json', 'r') as f:
    data = json.load(f)
    for item in data['threat_intelligence']:
        es.index(index='threat-intel', document=item)
```

### MISP Integration
```python
# Future enhancement: Export to MISP format
# MISP (Malware Information Sharing Platform)
```

## Roadmap

Future enhancements:
- [ ] API key support for premium feeds
- [ ] MISP format export
- [ ] Automated scheduling
- [ ] Email alerts for critical threats
- [ ] Machine learning for threat prioritization
- [ ] Tor network threat intelligence
- [ ] Dark web monitoring
- [ ] Threat actor attribution
- [ ] Integration with SOAR platforms

## Contributing

Contributions welcome! Suggested improvements:
- Additional threat intelligence sources
- New export formats
- Performance optimizations
- API integrations
- ML-based threat scoring

## License

MIT License - Free for security research and defensive use

## Contact

**Author:** cyb3rlop3 (Stanley Spears)
**Email:** stan.spears@outlook.com
**GitHub:** https://github.com/spearsies/Pythonscripts

## Acknowledgments

Thanks to all threat intelligence providers:
- CISA / US-CERT
- The Hacker News
- SANS Internet Storm Center
- OpenPhish
- And all open-source intelligence community members

---

**Remember:** Use this tool for authorized security operations only. Threat intelligence should be used to defend systems, not attack them.
