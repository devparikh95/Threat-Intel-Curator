import pytest
import json
from unittest.mock import patch, MagicMock
from src.mcp.server import nvd_query, fetch_rss, fetch_url, github_search

# 1. Test NVD Query
@patch('src.mcp.server.requests.get')
def test_nvd_query_success(mock_get):
    # Setup mock response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-9999",
                    "descriptions": [{"lang": "en", "value": "Exploit in PAN-OS routers."}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {"vulnerable": True, "criteria": "cpe:2.3:o:paloaltonetworks:pan-os:10.1.0"}
                                    ]
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    }
    mock_get.return_value = mock_resp
    
    result_str = nvd_query("CVE-2026-9999")
    result = json.loads(result_str)
    
    assert "error" not in result
    assert result["cve_id"] == "CVE-2026-9999"
    assert result["cvss_score"] == 9.8
    assert "cpe:2.3:o:paloaltonetworks:pan-os:10.1.0" in result["cpes"]
    assert "exploit in pan-os" in result["description"].lower()


# 2. Test Fetch RSS
@patch('src.mcp.server.feedparser.parse')
def test_fetch_rss_success(mock_parse):
    # Setup mock feed parser response
    mock_feed = MagicMock()
    mock_feed.bozo = False
    mock_feed.feed = {"title": "MSRC Blog", "description": "Microsoft Security Response Center"}
    
    mock_entry = MagicMock()
    mock_entry.get.side_effect = lambda key, default="": {
        "title": "New Advisory",
        "link": "https://msrc.microsoft.com/blog/1",
        "published": "2026-06-22",
        "summary": "This is a <p>paragraph description</p>.",
        "id": "advisory-1"
    }.get(key, default)
    
    mock_feed.entries = [mock_entry]
    mock_parse.return_value = mock_feed
    
    result_str = fetch_rss("https://msrc.microsoft.com/blog/feed")
    result = json.loads(result_str)
    
    assert "error" not in result
    assert result["feed_title"] == "MSRC Blog"
    assert len(result["entries"]) == 1
    assert result["entries"][0]["title"] == "New Advisory"
    # Verify HTML tags were stripped from summary
    assert "paragraph description" in result["entries"][0]["summary"]
    assert "<p>" not in result["entries"][0]["summary"]


# 3. Test Fetch URL
@patch('src.mcp.server.requests.get')
def test_fetch_url_success(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = """
    <html>
        <head>
            <title>Ignored</title>
            <style>body { color: red; }</style>
            <script>console.log("Ignored");</script>
        </head>
        <body>
            <h1>This is a Header</h1>
            <p>This is a paragraph.</p>
        </body>
    </html>
    """
    mock_get.return_value = mock_resp
    
    result = fetch_url("https://example.com/writeup")
    
    # Assert visible text is extracted and metadata is ignored
    assert "This is a Header" in result
    assert "This is a paragraph" in result
    assert "console.log" not in result
    assert "color: red" not in result


# 4. Test GitHub Search
@patch('src.mcp.server.requests.get')
def test_github_search_success(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "items": [
            {
                "name": "pan-os-exploit",
                "full_name": "user/pan-os-exploit",
                "html_url": "https://github.com/user/pan-os-exploit",
                "description": "PoC exploit for CVE-2026-9999",
                "stargazers_count": 42,
                "updated_at": "2026-06-22T10:00:00Z"
            }
        ]
    }
    mock_get.return_value = mock_resp
    
    result_str = github_search("CVE-2026-9999 PoC")
    result = json.loads(result_str)
    
    assert "error" not in result
    assert len(result) == 1
    assert result[0]["name"] == "pan-os-exploit"
    assert result[0]["stars"] == 42
    assert result[0]["html_url"] == "https://github.com/user/pan-os-exploit"
