import requests
from bs4 import BeautifulSoup
import tldextract
import re
from urllib.parse import urlparse

def is_phishing_link(url):
    try:
        parsed_url = urlparse(url)
        domain_info = tldextract.extract(url)
        domain = domain_info.domain
        subdomain = domain_info.subdomain

        if re.search(r'http[s]?://.*\.(ru|xyz|top|tk|cf|ga)', url):
            print(f"Suspicious domain: {url}")
            return True
        
        response = requests.get(url)
        content = response.text

        soup = BeautifulSoup(content, 'html.parser')
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            if tag.get('name') == 'description' and 'phishing' in tag.get('content', '').lower():
                print(f"Phishing keyword in meta description: {url}")
                return True

        if subdomain and domain not in ['example', 'trusted']:
            print(f"Suspicious subdomain: {url}")
            return True

        print(f"Seems legitimate: {url}")
        return False

    except Exception as e:
        print(f"Error processing {url}: {e}")
        return True

if __name__ == "__main__":
    test_urls = [
        "http://www.google.com",
        "http://www.wikipedia.org",
        "http://www.python.org",
        "http://www.github.com",
        "http://example.tk",
        "http://paypal-update.cf",
    ]

    for url in test_urls:
        print(f"Checking {url}...")
        result = is_phishing_link(url)
        print(f"Result: {'Phishing' if result else 'Legitimate'}\n")

