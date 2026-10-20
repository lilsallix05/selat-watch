import unittest
from watch.domain import normalize, score, brands, permutations

class DomainTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(normalize('HTTPS://MAYBANK.COM.MY./path'), 'maybank.com.my')
        self.assertEqual(normalize('faß.example'), 'xn--fa-hia.example')
        for value in ['javascript:alert(1)', 'user@example.com', 'a..example', '127.0.0.1', 'abc']:
            with self.assertRaises(ValueError): normalize(value)
    def test_brand_boundary(self):
        self.assertEqual(score({'domain':'login.maybank.com.my'})['score'], 0)
        self.assertGreater(score({'domain':'maybank.com.my.attacker.example'})['score'], 0)
        self.assertGreater(score({'domain':'mаybank-tebus.example'})['score'], 0)
    def test_profiles(self):
        self.assertEqual(len(brands()), 20)
        self.assertGreater(len(permutations('maybank')), 20)

if __name__ == '__main__': unittest.main()
