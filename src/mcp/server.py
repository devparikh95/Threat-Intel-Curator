from fastmcp import FastMCP
import requests
import feedparser
import os
import json
import re
from html.parser import HTMLParser
from typing import List, Optional

# Initialize FastMCP Server
mcp = FastMCP("Threat Intel Curator Tools")

class HTMLTextExtractor(HTMLParser):
    """
    Parser to extract visible text from HTML pages while ignoring styles,
    scripts, and metadata headers.
    """
    def __init__(self):
        super().__init__()
        self.result = []
        self.ignore = False

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style', 'head', 'title', 'meta', 'link'):
            self.ignore = True

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'head', 'title', 'meta', 'link'):
            self.ignore = False

    def handle_data(self, data):
        if not self.ignore:
            text = data.strip()
            if text:
                # Replace multiple spaces/newlines with a single space
                text = re.sub(r'\s+', ' ', text)
                self.result.append(text)

    def get_text(self) -> str:
        return "\n".join(self.result)


@mcp.tool()
def nvd_query(cve_id: str) -> str:
    """
    Query the National Vulnerability Database (NVD) API for details on a specific CVE ID.
    
    Args:
        cve_id: The CVE identifier (e.g., 'CVE-2021-44228').
        
    Returns:
        A JSON string containing cve_id, description, cvss_score, and affected CPEs.
    """
    cve_id = cve_id.strip().upper()
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    headers = {
        "User-Agent": "ThreatIntelCurator/1.0"
    }
    
    # Inject API key if configured
    nvd_key = os.environ.get("NVD_API_KEY")
    if nvd_key:
        headers["apiKey"] = nvd_key
        
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            return json.dumps({"error": f"NVD API returned status code {response.status_code}"})
            
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return json.dumps({"error": f"No details found for {cve_id}"})
            
        cve_data = vulnerabilities[0].get("cve", {})
        
        # 1. Extract Description (English)
        descriptions = cve_data.get("descriptions", [])
        description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
        
        # 2. Extract CVSS Score
        cvss_score = None
        metrics = cve_data.get("metrics", {})
        for metric_ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_ver, [])
            if metric_list:
                cvss_score = metric_list[0].get("cvssData", {}).get("baseScore")
                break
                
        # 3. Extract Affected CPEs
        cpes = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe_criteria = match.get("criteria")
                    if cpe_criteria and match.get("vulnerable", True):
                        cpes.append(cpe_criteria)
                        
        result = {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cpes": list(set(cpes)) # Deduplicate
        }
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Request failed: {str(e)}"})


@mcp.tool()
def fetch_rss(url: str) -> str:
    """
    Fetch and parse an RSS feed from a URL.
    
    Args:
        url: The RSS feed URL.
        
    Returns:
        A JSON string containing the title, description, and list of the latest 10 items.
    """
    try:
        feed = feedparser.parse(url)
        if feed.bozo:
            # RSS is technically malformed or unreachable
            if not feed.entries:
                return json.dumps({"error": f"Failed to parse RSS feed: {feed.bozo_exception}"})
                
        entries = []
        for entry in feed.entries[:10]: # Limit to 10 latest entries
            # Extract summary or description
            summary = entry.get("summary") or entry.get("description") or ""
            # Strip tags from summary if it's HTML
            parser = HTMLTextExtractor()
            parser.feed(summary)
            clean_summary = parser.get_text().strip()
            
            entries.append({
                "title": entry.get("title", ""),
                "link": entry.get("link", ""),
                "published": entry.get("published", entry.get("updated", "")),
                "summary": clean_summary[:500], # Truncate summary to keep context window clean
                "id": entry.get("id", "")
            })
            
        result = {
            "feed_title": feed.feed.get("title", ""),
            "feed_description": feed.feed.get("description", ""),
            "entries": entries
        }
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Failed to fetch RSS: {str(e)}"})


@mcp.tool()
def fetch_url(url: str) -> str:
    """
    Fetch the raw webpage content from a URL and extract its visible readable text.
    
    Args:
        url: The target website URL.
        
    Returns:
        A string containing the extracted text content.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatIntelCurator/1.0"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            return f"Error: Received HTTP status code {response.status_code} from {url}"
            
        # Parse visible text
        parser = HTMLTextExtractor()
        parser.feed(response.text)
        text = parser.get_text()
        
        # Deduplicate and clean up spacing
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        return "\n".join(lines)
        
    except Exception as e:
        return f"Error: Request failed: {str(e)}"


@mcp.tool()
def github_search(query: str) -> str:
    """
    Search GitHub repositories for PoCs, exploits, or research tools matching a query.
    
    Args:
        query: Search term (e.g., 'CVE-2026-9999 PoC').
        
    Returns:
        A JSON string containing search results matching the query.
    """
    url = f"https://api.github.com/search/repositories?q={query}&sort=stars&order=desc"
    
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ThreatIntelCurator/1.0"
    }
    
    # Inject GITHUB_TOKEN if configured
    git_token = os.environ.get("GITHUB_TOKEN")
    if git_token:
        headers["Authorization"] = f"Bearer {git_token}"
        
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            return json.dumps({"error": f"GitHub API returned status code {response.status_code}"})
            
        data = response.json()
        items = data.get("items", [])
        
        results = []
        for item in items[:5]: # Limit to 5 top repositories
            results.append({
                "name": item.get("name", ""),
                "full_name": item.get("full_name", ""),
                "html_url": item.get("html_url", ""),
                "description": item.get("description", ""),
                "stars": item.get("stargazers_count", 0),
                "updated_at": item.get("updated_at", "")
            })
            
        return json.dumps(results, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"Request failed: {str(e)}"})


def main():
    mcp.run()

if __name__ == "__main__":
    main()
