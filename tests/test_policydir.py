"""Ambient policy discovery: the munge-bucket layout, self-identification, walk-up,
collision-means-check-parent, and ambiguity failing closed."""
import os
import pathlib
import tempfile
import unittest

from certorail.host import load_policy
from certorail.policy import Policy
from certorail.policydir import AmbientPolicyError, find_policy, munge


class TestMunge(unittest.TestCase):
    def test_the_spelling(self) -> None:
        self.assertEqual(munge(pathlib.PurePosixPath("/")), "-")
        self.assertEqual(munge(pathlib.PurePosixPath("/srv/work/x")), "-srv-work-x")

    def test_the_documented_collision(self) -> None:
        self.assertEqual(
            munge(pathlib.PurePosixPath("/a/b-c")), munge(pathlib.PurePosixPath("/a/b/c"))
        )


class TestFindPolicy(unittest.TestCase):
    def setUp(self) -> None:
        self.base = pathlib.Path(tempfile.mkdtemp())
        os.environ["CERTORAIL_CONFIG_DIR"] = str(self.base)
        self.addCleanup(os.environ.pop, "CERTORAIL_CONFIG_DIR", None)
        # a real directory tree to probe from (resolve() must not invent paths)
        self.tree = pathlib.Path(tempfile.mkdtemp())
        (self.tree / "a" / "b" / "c").mkdir(parents=True)

    def _put(self, prefix: pathlib.Path, name: str, declared: str) -> pathlib.Path:
        bucket = self.base / munge(prefix)
        bucket.mkdir(exist_ok=True)
        file = bucket / name
        file.write_text(f'root = "{declared}"\n', encoding="utf-8")
        return file

    def test_the_nearest_ancestor_wins(self) -> None:
        deep = self.tree / "a" / "b" / "c"
        shallow_file = self._put(self.tree / "a", "team.toml", str(self.tree / "a"))
        found = find_policy(deep)
        assert found is not None
        self.assertEqual(found, (shallow_file, self.tree / "a"))
        # ... until a nearer one exists
        deep_file = self._put(deep, "mine.toml", str(deep))
        self.assertEqual(find_policy(deep), (deep_file, deep))

    def test_a_collision_is_check_parent(self) -> None:
        deep = self.tree / "a" / "b" / "c"
        # a file in the colliding bucket that identifies a DIFFERENT path ("/.../a/b-c")
        self._put(deep, "other.toml", str(self.tree / "a" / "b-c"))
        parent_file = self._put(self.tree / "a", "team.toml", str(self.tree / "a"))
        self.assertEqual(find_policy(deep), (parent_file, self.tree / "a"))

    def test_ambiguity_fails_closed(self) -> None:
        deep = self.tree / "a" / "b" / "c"
        self._put(deep, "one.toml", str(deep))
        self._put(deep, "two.toml", str(deep))
        with self.assertRaises(AmbientPolicyError):
            find_policy(deep)

    def test_a_file_without_root_fails_closed(self) -> None:
        deep = self.tree / "a" / "b" / "c"
        bucket = self.base / munge(deep)
        bucket.mkdir()
        (bucket / "anon.toml").write_text("policy-version = 1\n", encoding="utf-8")
        with self.assertRaises(AmbientPolicyError):
            find_policy(deep)

    def test_nothing_configured_is_none(self) -> None:
        self.assertIsNone(find_policy(self.tree / "a" / "b" / "c"))

    def test_load_policy_goes_through_the_strict_loader(self) -> None:
        deep = self.tree / "a" / "b" / "c"
        bucket = self.base / munge(deep)
        bucket.mkdir()
        (bucket / "here.toml").write_text(
            f'policy-version = 1\nroot = "{deep}"\n\n[[network]]\nhost = "api.github.com"\n',
            encoding="utf-8",
        )
        policy = load_policy(None, deep)
        self.assertIsInstance(policy, Policy)
        (rule,) = policy.network
        self.assertEqual(rule.host, "api.github.com")


if __name__ == "__main__":
    unittest.main()
