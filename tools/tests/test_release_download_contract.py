"""Every new publisher adapter must pass the shared offline HTTP contract."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import whatsapp_release_github as http
from release_http_contract import check_download_contract


def factory(transport):
    return http.GitHubClient('synthetic-contract-token', transport)


class DownloadContractTests(unittest.TestCase):
    def test_current_adapter_passes_shared_contract(self):
        self.assertEqual(check_download_contract(factory, http.APIError), 4)

    def test_contract_rejects_legacy_actions_header(self):
        def broken_factory(transport):
            def broken(request, **kwargs):
                if request.full_url.startswith('https://api.github.com/'):
                    request.add_header('Accept','application/octet-stream')
                return transport(request, **kwargs)
            return factory(broken)
        with self.assertRaises(AssertionError):
            check_download_contract(broken_factory, http.APIError)

    def test_contract_rejects_forwarded_credentials(self):
        def broken_factory(transport):
            def broken(request, **kwargs):
                if not request.full_url.startswith('https://api.github.com/'):
                    request.add_header('Authorization','synthetic-leak')
                return transport(request, **kwargs)
            return factory(broken)
        with self.assertRaises(AssertionError):
            check_download_contract(broken_factory, http.APIError)


if __name__ == '__main__': unittest.main()
