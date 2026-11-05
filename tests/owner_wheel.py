"""Run only against an installed research wheel via tools/owner_wheel.py."""

import copy
import importlib
import importlib.machinery
import importlib.metadata
import pickle
import sys
import unittest
from pathlib import Path

owner = importlib.import_module("kryvola_owner")


class InstalledOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = owner.OwnerKey()
        cls.evaluation = cls.key.evaluation_key()
        cls.evaluation_digest = owner.blob_digest(cls.evaluation)
        cls.pair = cls.key.encrypt_pair(bytes([255, 17]))

    def open(self, pair, evaluation_digest=None, result_digest=None):
        return self.key.open_result(
            pair,
            self.evaluation_digest if evaluation_digest is None else evaluation_digest,
            owner.blob_digest(pair) if result_digest is None else result_digest,
        )

    def test_installed_native_package(self):
        self.assertEqual(sys.version_info[:2], (3, 14))
        self.assertEqual(importlib.metadata.version("kryvola-owner"), "0.1.0.dev0")
        self.assertTrue(
            Path(str(owner.__file__)).resolve().is_relative_to(Path(sys.prefix).resolve())
        )
        native = importlib.import_module("kryvola_owner.kryvola_owner")
        self.assertTrue(
            Path(str(native.__file__)).resolve().is_relative_to(Path(sys.prefix).resolve())
        )
        self.assertTrue(
            any(str(native.__file__).endswith(s) for s in importlib.machinery.EXTENSION_SUFFIXES)
        )
        self.assertIs(owner.OwnerKey, native.OwnerKey)
        self.assertIs(owner.blob_digest, native.blob_digest)
        self.assertEqual(
            {name for name in dir(native) if not name.startswith("_")},
            {"OwnerKey", "blob_digest"},
        )

    def test_round_trip_fixed_uint8_pair(self):
        self.assertIsInstance(self.evaluation, bytes)
        self.assertGreater(len(self.evaluation), 0)
        self.assertEqual(self.open(self.pair), bytes([255, 17]))
        self.assertEqual(self.open(self.key.encrypt_pair(bytes([0, 255]))), bytes([0, 255]))

    def test_boundaries_fail_closed(self):
        for kwargs in ({"evaluation_digest": bytes(32)}, {"result_digest": bytes(32)}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, "^OWNER_BINDING$"):
                self.open(self.pair, **kwargs)
        for digest in (b"", bytes(31), bytes(33)):
            with self.assertRaisesRegex(ValueError, "^OWNER_DIGEST$"):
                self.open(self.pair, evaluation_digest=digest)
            with self.assertRaisesRegex(ValueError, "^OWNER_DIGEST$"):
                self.open(self.pair, result_digest=digest)
        for pair in (b"", self.pair[:-1], self.pair + b"x"):
            with self.assertRaisesRegex(ValueError, "^OWNER_FRAMING$"):
                self.open(pair)
        malformed = bytearray(self.pair)
        malformed[16] ^= 1
        with self.assertRaisesRegex(ValueError, "^OWNER_NATIVE$"):
            self.open(bytes(malformed))
        with self.assertRaisesRegex(ValueError, "^OWNER_SIZE$"):
            self.open(bytes(2 * ((1 << 20) + 8) + 1))

    def test_invalid_plaintext_and_types(self):
        for values in (b"", b"x", b"xxx"):
            with self.assertRaisesRegex(ValueError, "^OWNER_SHAPE$"):
                self.key.encrypt_pair(values)
        for values in ([1, 256], [-1, 2], "secret-marker", bytearray(b"ab")):
            with self.assertRaises(TypeError):
                self.key.encrypt_pair(values)
        with self.assertRaises(TypeError):
            self.key.open_result("secret-marker", bytes(32), bytes(32))

    def test_handle_has_no_serialization_or_secret_attributes(self):
        self.assertEqual(repr(self.key), "<kryvola_owner.OwnerKey opaque>")
        self.assertEqual(str(self.key), repr(self.key))
        public = {name for name in dir(self.key) if not name.startswith("_")}
        self.assertEqual(public, {"evaluation_key", "encrypt_pair", "open_result"})
        self.assertFalse(hasattr(self.key, "__dict__"))
        with self.assertRaises(AttributeError):
            self.key.client_key = b"secret-marker"
        for action in (pickle.dumps, copy.copy, copy.deepcopy):
            with self.assertRaises(TypeError) as raised:
                action(self.key)
            self.assertNotIn("secret-marker", str(raised.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
