import unittest
from dns.resolver import resolve_domain

class TestDNSResolver(unittest.TestCase):
    
    def test_valid_domain(self):
        domain = "example.com"
        ip_addresses = resolve_domain(domain)
        self.assertTrue(len(ip_addresses) > 0, f"Expected IP addresses for {domain}, got {ip_addresses}")
        self.assertTrue(all(isinstance(ip, str) for ip in ip_addresses), "All IP addresses should be strings")


    def test_nonexistent_domain(self):
        domain = "nonexistentdomain.com"
        ip_addresses = resolve_domain(domain)
        self.assertEqual(ip_addresses, [], f"Expected no IP addresses for {domain}, got {ip_addresses}")

    def test_numeric_domain(self):
        domain = "123.456.789.com"
        ip_addresses = resolve_domain(domain)
        self.assertTrue(len(ip_addresses) > 0, f"Expected IP addresses for {domain}, got {ip_addresses}")

    def test_subdomain(self):
        domain = "sub.example.com"
        ip_addresses = resolve_domain(domain)
        self.assertTrue(isinstance(ip_addresses, list))


if __name__ == "__main__":
    unittest.main()


