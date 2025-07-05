import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse


def diff_month(d1, d2):
    return (d1.year - d2.year) * 12 + d1.month - d2.month


def generate_data_set(url):
    data_set = []

    if not re.match(r"^https?", url):
        url = "http://" + url

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        response = ""
        soup = -999

    domain = re.findall(r"://([^/]+)/?", url)[0]
    if domain.startswith("www."):
        domain = domain.replace("www.", "")
    whois_response = whois.whois(domain)

    try:
        rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
            "name": domain
        })
        global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
    except:
        global_rank = -1

    # 1. having_IP_Address
    try:
        ipaddress.ip_address(url)
        data_set.append(-1)
    except:
        data_set.append(1)

    # 2. URL_Length
    if len(url) < 54:
        data_set.append(1)
    elif 54 <= len(url) <= 75:
        data_set.append(0)
    else:
        data_set.append(-1)

    # 3. Shortening_Service
    shortening_services = re.compile(r"(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl\.com|"
                                     r"tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|"
                                     r"twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|"
                                     r"post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|"
                                     r"short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|"
                                     r"db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|"
                                     r"twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|"
                                     r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|"
                                     r"tweez\.me|v\.gd|tr\.im|link\.zip\.net)")
    data_set.append(-1 if shortening_services.search(url) else 1)

    # 4. having_At_Symbol
    data_set.append(-1 if "@" in url else 1)

    # 5. double_slash_redirecting
    if url.rfind('//') > 6:
        data_set.append(-1)
    else:
        data_set.append(1)

    # 6. Prefix_Suffix
    data_set.append(-1 if re.search(r"https?://[^/]*-[^/]*\.", url) else 1)

    # 7. having_Sub_Domain
    dot_count = url.count('.')
    if dot_count == 1:
        data_set.append(1)
    elif dot_count == 2:
        data_set.append(0)
    else:
        data_set.append(-1)

    # 8. SSLfinal_State
    data_set.append(1 if url.startswith("https://") else -1)

    # 9. Domain_registeration_length
    try:
        expiration_date = whois_response.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        today = datetime.now()
        registration_length = abs((expiration_date - today).days)
        data_set.append(1 if registration_length / 365 > 1 else -1)
    except:
        data_set.append(-1)

    # 10. Favicon
    try:
        found = False
        for head in soup.find_all('head'):
            for link_tag in head.find_all('link', href=True):
                href = link_tag['href']
                if domain in href or len(href.split('.')) == 2:
                    data_set.append(1)
                    found = True
                    break
            if found:
                break
        if not found:
            data_set.append(-1)
    except:
        data_set.append(-1)

    # 11. port
    data_set.append(-1 if ':' in domain else 1)

    # 12. HTTPS_token
    data_set.append(1 if url.startswith("https://") else -1)

    # 13. Request_URL
    try:
        total, success = 0, 0
        for tag in soup.find_all(['img', 'audio', 'embed', 'iframe'], src=True):
            src = tag['src']
            if domain in src or len(src.split('.')) == 2:
                success += 1
            total += 1
        perc = success / total * 100 if total else 100
        data_set.append(1 if perc < 22 else 0 if perc < 61 else -1)
    except:
        data_set.append(1)

    # 14. URL_of_Anchor
    try:
        anchors = soup.find_all('a', href=True)
        total = len(anchors)
        unsafe = len([a for a in anchors if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or domain not in a['href']])
        perc = unsafe / total * 100 if total else 0
        data_set.append(1 if perc < 31 else 0 if perc < 67 else -1)
    except:
        data_set.append(1)

    # 15. Links_in_tags
    try:
        links = soup.find_all(['link', 'script'], href=True) + soup.find_all('script', src=True)
        total, success = len(links), 0
        for tag in links:
            ref = tag.get('href') or tag.get('src')
            if ref and (domain in ref or len(ref.split('.')) == 2):
                success += 1
        perc = success / total * 100 if total else 100
        data_set.append(1 if perc < 17 else 0 if perc < 81 else -1)
    except:
        data_set.append(-1)

    # 16. SFH
    try:
        forms = soup.find_all('form', action=True)
        if not forms:
            data_set.append(1)
        else:
            for form in forms:
                action = form['action']
                if action in ["", "about:blank"]:
                    data_set.append(-1)
                elif domain not in action:
                    data_set.append(0)
                else:
                    data_set.append(1)
                break
    except:
        data_set.append(-1)

    # 17. Submitting_to_email
    data_set.append(-1 if re.search(r"(mailto:|mail\()", response.text) else 1)

    # 18. Abnormal_URL
    try:
        data_set.append(-1 if domain not in whois_response.domain_name else 1)
    except:
        data_set.append(-1)

    # 19. Redirect
    try:
        redirects = len(response.history)
        data_set.append(-1 if redirects <= 1 else 0 if redirects <= 4 else 1)
    except:
        data_set.append(-1)

    # 20. on_mouseover
    data_set.append(1 if re.search(r"onmouseover\s*=", response.text) else -1)

    # 21. RightClick
    data_set.append(1 if "event.button==2" in response.text else -1)

    # 22. popUpWindow
    data_set.append(1 if "alert(" in response.text else -1)

    # 23. Iframe
    data_set.append(1 if "<iframe" in response.text.lower() else -1)

    # 24. age_of_domain
    try:
        creation_date = whois_response.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = diff_month(datetime.now(), creation_date)
        data_set.append(1 if age >= 6 else -1)
    except:
        data_set.append(-1)

    # 25. DNSRecord
    try:
        d = whois.whois(domain)
        data_set.append(1 if registration_length / 365 > 1 else -1)
    except:
        data_set.append(-1)

    # 26. web_traffic
    try:
        alexa_rank = BeautifulSoup(
            urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml"
        ).find("REACH")["RANK"]
        alexa_rank = int(alexa_rank)
        data_set.append(1 if alexa_rank < 100000 else 0)
    except:
        data_set.append(-1)

    # 27. Page_Rank
    data_set.append(-1 if 0 < global_rank < 100000 else 1)

    # 28. Google_Index
    try:
        result = list(search(url, num=5))
        data_set.append(1 if result else -1)
    except:
        data_set.append(-1)

    # 29. Links_pointing_to_page
    try:
        num_links = len(re.findall(r"<a\s+href=", response.text))
        data_set.append(1 if num_links == 0 else 0 if num_links <= 2 else -1)
    except:
        data_set.append(-1)

    # 30. Statistical_report
    try:
        suspicious_urls = re.compile(r"(at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly)")
        ip = socket.gethostbyname(domain)
        suspicious_ips = re.compile(r"(146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158)")
        if suspicious_urls.search(url) or suspicious_ips.search(ip):
            data_set.append(-1)
        else:
            data_set.append(1)
    except:
        data_set.append(-1)

    return data_set
if __name__ == "__main__":
    test_url = input("Enter a URL: ")
    features = generate_data_set(test_url)
    print("\nExtracted Features:")
    for i, feature in enumerate(features, start=1):
        print(f"Feature {i}: {feature}")
