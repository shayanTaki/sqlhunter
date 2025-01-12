import requests
from urllib.parse import urlencode, urlparse, parse_qs
import time
import os

def animated_print(text, delay=0.1):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

class SQLInjectionTester:
    def __init__(self, url, method="GET", data=None, headers=None, cookies=None, delay=0, timeout=10):
        """
        shirdalcode.ir
        """
        self.url = url
        self.method = method.upper()
        self.data = data
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.delay = delay
        self.timeout = timeout
        self.payloads = self.generate_payloads()
        self.vulnerabilities = {} # Dictionary to store vulnerabilities and errors