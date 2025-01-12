import requests
from urllib.parse import urlencode, urlparse, parse_qs
import time
import os

def animated_print(text, delay=0.1):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()