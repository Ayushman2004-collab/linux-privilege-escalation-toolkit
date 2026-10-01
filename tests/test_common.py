import unittest
from modules.common import mode_string


class CommonTests(unittest.TestCase):
    def test_missing_path(self):
        self.assertEqual(mode_string("/definitely/not/a/real/path"), "unavailable")


if __name__ == "__main__":
    unittest.main()
