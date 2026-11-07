"""Worker package boundaries; fixture symbols are not native build evidence."""

import unittest

from tools import cpu_boundary


class CpuBoundaryTests(unittest.TestCase):
    def test_worker_runtime_and_binary_are_distinct_from_owner_packages(self):
        tree = "kryvola-cpu-evaluator v0.1.0\ntfhe v1.8.1\nblake3 v1.8.7"
        symbols = "0000 T kryvola_cpu_evaluator::evaluate"
        cpu_boundary.inspect(tree, symbols)
        for dependency in ("kryvola-owner-crypto", "kryvola-owner-python", "pyo3"):
            with self.subTest(dependency=dependency), self.assertRaises(ValueError):
                cpu_boundary.inspect(tree + "\n" + dependency + " v0.1.0", symbols)
        for linked in ("kryvola_owner_crypto::OwnerKey::generate", "pyo3::module"):
            with self.subTest(linked=linked), self.assertRaises(ValueError):
                cpu_boundary.inspect(tree, symbols + "\n0000 T " + linked)
        with self.assertRaises(ValueError):
            cpu_boundary.inspect(tree, "")
