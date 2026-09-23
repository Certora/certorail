"""One request, one governing rule: overlapping ``[[network]]`` rules are refused at load, and the
analysis and the broker read a URL's path the same way, so the rule the broker finds is the rule
the analysis proved."""
import unittest

from certorail.analysis import Named, StaticPath, url_path_location
from certorail.policy import Policy, network, networks_overlap


class TestOverlap(unittest.TestCase):
    def test_what_can_coincide_overlaps(self) -> None:
        self.assertTrue(networks_overlap(network("api.example.com"), network("api.example.com")))
        self.assertTrue(networks_overlap(network("api.example.com", path="/public/**"), network("api.example.com")))
        self.assertTrue(networks_overlap(network("a.corp.example.com"), network("*.corp.example.com")))
        self.assertTrue(networks_overlap(network("*.corp.example.com"), network("*.example.com")))
        self.assertTrue(networks_overlap(
            network("api.example.com", methods=["GET"]), network("api.example.com", methods=["GET", "POST"])
        ))
        self.assertTrue(networks_overlap(
            network("api.example.com", path="/v1/**"), network("api.example.com", path="/v1/<[a-z]+>")
        ))

    def test_what_cannot_coincide_does_not(self) -> None:
        self.assertFalse(networks_overlap(network("api.example.com"), network("www.example.com")))
        self.assertFalse(networks_overlap(network("example.com"), network("*.example.com")))  # not the suffix itself
        self.assertFalse(networks_overlap(
            network("api.example.com", methods=["GET"]), network("api.example.com", methods=["POST"])
        ))
        self.assertFalse(networks_overlap(
            network("api.example.com"), network("api.example.com", schemes=["http"], ports=[8080])
        ))
        self.assertFalse(networks_overlap(
            network("api.example.com", path="/public/**"), network("api.example.com", path="/private/**")
        ))

    def test_the_policy_refuses_an_overlapping_pair(self) -> None:
        with self.assertRaisesRegex(ValueError, "overlap"):
            Policy.allow(network=[network("api.example.com", path="/public/**"), network("api.example.com")])
        Policy.allow(network=[network("api.example.com", path="/public/**"), network("api.example.com", path="/data/**")])


class TestPathReading(unittest.TestCase):
    def test_the_raw_path_is_placed(self) -> None:
        self.assertEqual(url_path_location("/v1/items"), StaticPath((Named("v1"), Named("items")), absolute=True))
        self.assertEqual(url_path_location(""), StaticPath((), absolute=True))  # the server root

    def test_a_path_that_decodes_to_something_else_has_no_location(self) -> None:
        for path in ("/public/%2e%2e/data", "/public/%2E%2E/data", "/public/a%2fb", "/public/.."):
            with self.subTest(path=path):
                self.assertIsNone(url_path_location(path))


if __name__ == "__main__":
    unittest.main()
