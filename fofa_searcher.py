# -*- coding: utf-8 -*-
import base64
import requests
import json
import os
import sys
import re
from multiprocessing.pool import ThreadPool
import threading
from datetime import datetime

API_KEY = "PUT UR TOKEN HERE"
SIZE_DEFAULT = 100
OUTPUT_DIR = "results"
CONCURRENT_THREADS = 10

VALID_FIELDS = [
    'ip', 'port', 'protocol', 'base_protocol', 'title', 'host', 'domain', 
    'server', 'country', 'region', 'city', 'header', 'country_name', 'link', 
    'jarm', 'icp', 'latitude', 'longitude', 'banner', 'os', 'asn', 'org', 
    'status_code', 'header_hash', 'banner_hash', 'banner_fid', 'product', 
    'product_category', 'lastupdatetime', 'cname', 'icon_hash', 'cname_domain', 
    'body', 'structinfo', 'fid', 'icon',
    
    'tls.version', 'tls.ja3s',
    
    'cert', 'cert.sn', 'cert.not_after', 'cert.not_before', 'cert.domain', 
    'cert.subject.org', 'cert.subject.cn', 'cert.issuer.org', 'cert.issuer.cn', 
    'cert.is_valid', 'cert.is_match', 'cert.is_equal'
]

FIELD_DISPLAY_NAMES = {
    'ip': 'IP',
    'port': 'Port',
    'protocol': 'Protocol',
    'base_protocol': 'Base Protocol',
    'title': 'Title',
    'host': 'Host',
    'domain': 'Domain',
    'server': 'Server',
    'country': 'Country',
    'region': 'Region',
    'city': 'City',
    'header': 'HTTP Header',
    'country_name': 'Country',
    'link': 'Link',
    'jarm': 'JARM Fingerprint',
    'icp': 'ICP License',
    'latitude': 'Latitude',
    'longitude': 'Longitude',
    'banner': 'Banner',
    'os': 'Operating System',
    'asn': 'ASN',
    'org': 'Organization',
    'status_code': 'HTTP Status Code',
    'header_hash': 'Header Hash',
    'banner_hash': 'Banner Hash',
    'banner_fid': 'Banner FID',
    'product': 'Product',
    'product_category': 'Product Category',
    'lastupdatetime': 'Last Update Time',
    'cname': 'CNAME',
    'icon_hash': 'Icon Hash',
    'cname_domain': 'CNAME Domain',
    'body': 'Body',
    'structinfo': 'Structure Info',
    'fid': 'FID',
    'icon': 'Icon',
    'tls.version': 'TLS Version',
    'tls.ja3s': 'TLS JA3S',
    'cert': 'Certificate',
    'cert.sn': 'Certificate Serial Number',
    'cert.not_after': 'Certificate Not After',
    'cert.not_before': 'Certificate Not Before',
    'cert.domain': 'Certificate Domain',
    'cert.subject.org': 'Certificate Subject Organization',
    'cert.subject.cn': 'Certificate Subject Common Name',
    'cert.issuer.org': 'Certificate Issuer Organization',
    'cert.issuer.cn': 'Certificate Issuer Common Name',
    'cert.is_valid': 'Certificate Is Valid',
    'cert.is_match': 'Certificate Is Match',
    'cert.is_equal': 'Certificate Is Equal'
}

lock = threading.Lock()
saved_results = set()
pages_completed = 0
output_file = None

def sanitize_filename(filename):
    return re.sub(r'[<>:"/\\|?*]', '_', filename)

def generate_output_filename(fields_string, query):
    first_field = fields_string.split(',')[0].strip()
    
    query_clean = re.sub(r'[^a-zA-Z0-9]', '_', query[:30])
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if first_field in ['domain', 'host', 'cname', 'cname_domain']:
        filename = "domains_%s_%s.txt" % (query_clean, timestamp)
    elif first_field == 'ip':
        filename = "ips_%s_%s.txt" % (query_clean, timestamp)
    elif first_field == 'title':
        filename = "titles_%s_%s.txt" % (query_clean, timestamp)
    elif first_field == 'port':
        filename = "ports_%s_%s.txt" % (query_clean, timestamp)
    elif first_field == 'protocol':
        filename = "protocols_%s_%s.txt" % (query_clean, timestamp)
    elif first_field == 'server':
        filename = "servers_%s_%s.txt" % (query_clean, timestamp)
    elif first_field == 'os':
        filename = "os_%s_%s.txt" % (query_clean, timestamp)
    elif first_field == 'asn':
        filename = "asns_%s_%s.txt" % (query_clean, timestamp)
    elif first_field == 'org':
        filename = "orgs_%s_%s.txt" % (query_clean, timestamp)
    elif first_field == 'country' or first_field == 'country_name':
        filename = "countries_%s_%s.txt" % (query_clean, timestamp)
    elif first_field == 'city':
        filename = "cities_%s_%s.txt" % (query_clean, timestamp)
    elif first_field == 'product':
        filename = "products_%s_%s.txt" % (query_clean, timestamp)
    elif first_field.startswith('cert.'):
        filename = "certificates_%s_%s.txt" % (query_clean, timestamp)
    elif first_field.startswith('tls.'):
        filename = "tls_%s_%s.txt" % (query_clean, timestamp)
    else:
        filename = "fofa_%s_%s.txt" % (query_clean, timestamp)
    
    return os.path.join(OUTPUT_DIR, sanitize_filename(filename))

def format_output_line(item, fields_string):
    if not isinstance(item, list):
        return item.encode('utf-8')
    
    fields = [f.strip() for f in fields_string.split(',')]
    
    if len(fields) == 1:
        field_type = fields[0]
        value = str(item[0]) if len(item) > 0 else ""
        
        if not value or value == "None":
            return None
        
        display_name = FIELD_DISPLAY_NAMES.get(field_type, field_type.upper())
        
        if field_type == 'port':
            return "Port: %s" % value
        elif field_type == 'ip':
            return "IP: %s" % value
        elif field_type == 'protocol':
            return "Protocol: %s" % value
        elif field_type == 'base_protocol':
            return "Base Protocol: %s" % value
        elif field_type == 'title':
            if len(value) > 100:
                value = value[:97] + "..."
            return "Title: %s" % value
        elif field_type == 'host' or field_type == 'domain':
            return "%s: %s" % (display_name, value)
        elif field_type == 'server':
            return "Server: %s" % value
        elif field_type == 'country' or field_type == 'country_name':
            return "Country: %s" % value
        elif field_type == 'region':
            return "Region: %s" % value
        elif field_type == 'city':
            return "City: %s" % value
        elif field_type == 'os':
            return "OS: %s" % value
        elif field_type == 'asn':
            return "ASN: %s" % value
        elif field_type == 'org':
            return "Organization: %s" % value
        elif field_type == 'status_code':
            return "HTTP Status: %s" % value
        elif field_type == 'product':
            return "Product: %s" % value
        elif field_type == 'jarm':
            return "JARM: %s" % value
        elif field_type == 'icp':
            return "ICP License: %s" % value
        elif field_type == 'banner':
            if len(value) > 150:
                value = value[:147] + "..."
            return "Banner: %s" % value
        elif field_type == 'header':
            if len(value) > 100:
                value = value[:97] + "..."
            return "Header: %s" % value
        elif field_type == 'body':
            if len(value) > 100:
                value = value[:97] + "..."
            return "Body: %s" % value
        elif field_type == 'cname':
            return "CNAME: %s" % value
        elif field_type == 'latitude':
            return "Latitude: %s" % value
        elif field_type == 'longitude':
            return "Longitude: %s" % value
        elif field_type.startswith('tls.'):
            return "TLS %s: %s" % (field_type.split('.')[1].upper(), value)
        elif field_type.startswith('cert.'):
            cert_field = field_type.split('.')[1] if '.' in field_type else 'data'
            return "Cert %s: %s" % (cert_field.replace('_', ' ').title(), value)
        else:
            return "%s: %s" % (display_name, value)
    
    output_parts = []
    for i, field in enumerate(fields):
        if i < len(item):
            value = str(item[i])
            if value and value != "None":
                display_name = FIELD_DISPLAY_NAMES.get(field, field)
                
                if field == 'port':
                    output_parts.append("Port:%s" % value)
                elif field == 'ip':
                    output_parts.append(value) 
                elif field == 'host' or field == 'domain':
                    output_parts.append(value)
                elif field == 'title':
                    if len(value) > 50:
                        value = value[:47] + "..."
                    output_parts.append("[%s]" % value)
                elif field == 'protocol':
                    output_parts.append("(%s)" % value)
                elif field == 'status_code':
                    output_parts.append("[%s]" % value)
                elif field == 'server':
                    if len(value) > 30:
                        value = value[:27] + "..."
                    output_parts.append("Server:%s" % value)
                elif field == 'country':
                    output_parts.append("{%s}" % value)
                else:
                    if len(output_parts) > 2:
                        output_parts.append("%s=%s" % (field, value))
                    else:
                        output_parts.append(value)
    
    return " | ".join(output_parts) if output_parts else None

def normalize_string(string_value):
    if not string_value:
        return ""
    
    cleaned = string_value.strip().lower()
    
    if '.' in cleaned and ('http' in cleaned or 'www.' in cleaned):
        if cleaned.startswith("https://"):
            cleaned = cleaned[8:]
        elif cleaned.startswith("http://"):
            cleaned = cleaned[7:]
        if cleaned.startswith("www."):
            cleaned = cleaned[4:]
    
    return cleaned

def load_existing_results():
    existing = set()
    if output_file and os.path.exists(output_file):
        with open(output_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    if ": " in line and not line.startswith("=="):
                        parts = line.split(": ", 1)
                        if len(parts) == 2:
                            key = parts[1].lower()
                        else:
                            key = normalize_string(line)
                    else:
                        key = normalize_string(line)
                    existing.add(key)
    return existing

def print_banner():
    banner = """
================================================================================
                    FOFA API THREADED SEARCHER
================================================================================
    [+] Threaded Concurrent Requests : %d
    [+] Results Per Page            : %d
    [+] Output Directory            : %s
    [+] API Endpoint                : en.fofa.info
    [+] Valid Fields Loaded         : %d fields
    [+] Smart Output Formatting     : Enabled (All Fields)
================================================================================
""" % (CONCURRENT_THREADS, SIZE_DEFAULT, OUTPUT_DIR, len(VALID_FIELDS))
    print banner

def ensure_output_dir():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print("[+] Created output directory: %s" % OUTPUT_DIR)

def get_valid_query():
    while True:
        user_query = raw_input("[?] Enter FOFA query: ").strip()
        
        if user_query:
            return user_query
        
        print("\n[!] ERROR: Query cannot be empty!")
        retry = raw_input("[?] Try again? (y/n): ").strip().lower()
        
        if retry != 'y':
            print("\n[!] Operation cancelled by user.")
            sys.exit(0)
        print("") 

def get_valid_max_page():
    while True:
        max_page_input = raw_input("[?] Enter max page to scrape [Default: 1]: ").strip()
        
        if not max_page_input:
            return 1
        
        try:
            max_page = int(max_page_input)
            if max_page > 0:
                return max_page
            else:
                print("[!] ERROR: Page number must be greater than 0!")
        except ValueError:
            print("[!] ERROR: Please enter a valid number!")

def validate_fields(fields_string):
    if not fields_string:
        return True, "host,ip,port"
    
    field_list = [f.strip() for f in fields_string.split(',')]
    
    invalid_fields = []
    for field in field_list:
        if field not in VALID_FIELDS:
            invalid_fields.append(field)
    
    if invalid_fields:
        return False, invalid_fields
    return True, fields_string

def get_valid_fields():
    print("\n[?] Field examples: host,ip,port,title,domain,cert.sn,tls.version")
    print("[?] Type 'list' to see all valid fields")
    
    while True:
        fields_input = raw_input("[?] Enter fields [Default: host,ip,port]: ").strip().lower()
        
        if fields_input == 'list':
            print("\n[+] Valid FOFA Fields (%d total):" % len(VALID_FIELDS))
            print("-" * 60)
            basic_fields = ['ip', 'port', 'protocol', 'base_protocol', 'host', 'domain', 'title', 'server', 'country', 'region', 'city', 'os', 'asn', 'org', 'banner', 'header', 'body', 'cname', 'icp', 'jarm', 'icon', 'fid', 'status_code', 'product']
            cert_fields = ['cert', 'cert.sn', 'cert.not_after', 'cert.not_before', 'cert.domain', 'cert.subject.org', 'cert.subject.cn', 'cert.issuer.org', 'cert.issuer.cn', 'cert.is_valid', 'cert.is_match', 'cert.is_equal']
            tls_fields = ['tls.version', 'tls.ja3s']
            
            print("\n--- Basic Fields (%d) ---" % len(basic_fields))
            for i in range(0, len(basic_fields), 5):
                print("  " + ", ".join(basic_fields[i:i+5]))
            
            print("\n--- Certificate Fields (cert.*) (%d) ---" % len(cert_fields))
            for i in range(0, len(cert_fields), 5):
                print("  " + ", ".join(cert_fields[i:i+5]))
            
            print("\n--- TLS Fields (tls.*) (%d) ---" % len(tls_fields))
            print("  " + ", ".join(tls_fields))
            
            print("\n[!] Use format: field1,field2,field3 (e.g., host,ip,port,cert.sn)")
            print("-" * 60 + "\n")
            continue
        
        if not fields_input:
            return "host,ip,port"
        
        is_valid, result = validate_fields(fields_input)
        
        if is_valid:
            return result
        else:
            print("\n[!] ERROR: Invalid field(s): %s" % ', '.join(result))
            print("[!] Type 'list' to see all valid fields")
            
            retry = raw_input("[?] Try again with valid fields? (y/n): ").strip().lower()
            if retry != 'y':
                print("\n[!] Operation cancelled by user.")
                sys.exit(0)
            print("") 

def get_result_label(fields_string):
    fields = [f.strip() for f in fields_string.split(',')]
    first_field = fields[0]
    
    label_map = {
        'domain': 'domains/hosts',
        'host': 'domains/hosts',
        'cname': 'CNAME records',
        'cname_domain': 'CNAME domains',
        'ip': 'IP addresses',
        'title': 'titles',
        'protocol': 'protocols',
        'base_protocol': 'base protocols',
        'port': 'ports',
        'server': 'servers',
        'os': 'operating systems',
        'country': 'countries',
        'country_name': 'countries',
        'region': 'regions',
        'city': 'cities',
        'asn': 'ASNs',
        'org': 'organizations',
        'product': 'products',
        'status_code': 'HTTP status codes',
        'jarm': 'JARM fingerprints',
        'icp': 'ICP licenses',
        'banner': 'banners',
        'header': 'HTTP headers',
    }
    
    if first_field in label_map:
        return label_map[first_field]
    elif first_field.startswith('cert.'):
        return "certificate records"
    elif first_field.startswith('tls.'):
        return "TLS records"
    else:
        return "unique records"

def fetch_page(args):
    global pages_completed
    url, q_base64, fields, page, max_page = args
    
    params = {
        'key': API_KEY,
        'qbase64': q_base64,
        'size': SIZE_DEFAULT,
        'page': page,
        'fields': fields
    }

    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data_json = response.json()
            if data_json.get("error") == True:
                return
            
            results = data_json.get("results", [])
            if not results:
                return

            with lock:
                with open(output_file, "a") as f:
                    for item in results:
                        line = format_output_line(item, fields)
                        
                        if not line:
                            continue
                        
                        if isinstance(item, list) and len(item) > 0:
                            check_value = str(item[0])
                        else:
                            check_value = line
                        
                        normalized = normalize_string(check_value)
                        
                        if normalized and normalized not in saved_results:
                            f.write(line + "\n")
                            saved_results.add(normalized)
        
    except Exception as e:
        pass
    finally:
        with lock:
            pages_completed += 1
            sys.stdout.write("\r[+] Progress: (%d/%d) pages processed" % (pages_completed, max_page))
            sys.stdout.flush()

def main():
    global saved_results, output_file
    
    print_banner()
    ensure_output_dir()
    user_query = get_valid_query()
    max_page = get_valid_max_page()
    fields = get_valid_fields()
    output_file = generate_output_filename(fields, user_query)
    q_base64 = base64.b64encode(user_query)
 
    print("\n" + "=" * 80)
    print("[+] CONFIGURATION SUMMARY")
    print("=" * 80)
    print("[+] Query: %s" % user_query)
    print("[+] Max pages: %d" % max_page)
    print("[+] Fields: %s" % fields)
    print("[+] Output file: %s" % output_file)
    print("=" * 80)
    
    url = "https://en.fofa.info/api/v1/search/all"
    
    saved_results = load_existing_results()
    if saved_results:
        print("[+] Loaded %d existing unique results from previous session" % len(saved_results))
    
    print("\n[+] Starting multi-threaded download with %d concurrent threads..." % CONCURRENT_THREADS)
    print("[+] Target pages: %d" % max_page)
    print("-" * 80)
    
    tasks = [(url, q_base64, fields, p, max_page) for p in range(1, max_page + 1)]
    
    pool = ThreadPool(CONCURRENT_THREADS)
    pool.map(fetch_page, tasks)
    pool.close()
    pool.join()
    result_label = get_result_label(fields)
    
    print("\n" + "-" * 80)
    print("[+] SUCCESS: All tasks completed!")
    print("[+] Total unique %s saved: %d" % (result_label, len(saved_results)))
    print("[+] Results saved to: %s" % output_file)
    
    if len(saved_results) > 0:
        print("\n[+] Sample output (first 5 results):")
        print("-" * 80)
        with open(output_file, "r") as f:
            for i, line in enumerate(f):
                if i < 5:
                    print("  %s" % line.strip())
                else:
                    remaining = len(saved_results) - 5
                    if remaining > 0:
                        print("  ... and %d more" % remaining)
                    break
    
    print("=" * 80)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting gracefully...")
        sys.exit(0)
    except Exception as e:
        print("\n[!] Fatal error: %s" % str(e))
        sys.exit(1)
