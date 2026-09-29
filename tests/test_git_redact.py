"""Tests for git-redact: rules, round trips, and the real git integration (clean, smudge, process).

Run:  python -m unittest discover -s tests -v
Fake secrets are assembled at runtime so that no token-shaped literal sits in this file.
"""
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "git-redact")
_loader = importlib.machinery.SourceFileLoader("git_redact", SCRIPT)
_spec = importlib.util.spec_from_loader("git_redact", _loader)
gr = importlib.util.module_from_spec(_spec)
_loader.exec_module(gr)

A36 = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"  # 36 mixed chars


def fake(kind):
    return {
        "github-token": "gh" + "p_" + A36,
        "gitlab-token": "gl" + "pat-" + A36[:20],
        "slack-token": "xo" + "xb-" + "1234567890-" + A36[:24],
        "discord-bot-token": "M" + A36[:25] + "." + "Gx1y2z" + "." + A36[:30],
        "telegram-bot-token": "1234567890" + ":AA" + (A36 + A36)[:33],
        "aws-access-key-id": "AK" + "IA" + "ABCDEFGHIJ234567",
        "google-api-key": "AI" + "za" + (A36 + "xyz")[:35],
        "stripe-key": "sk" + "_live_" + A36[:24],
        "openai-key": "sk" + "-proj-" + A36 + A36[:10],
        "npm-token": "np" + "m_" + A36,
        "sendgrid-key": "SG" + "." + A36[:22] + "." + (A36 + A36)[:43],
        "jwt": "ey" + "JhbGciOiJIUzI1NiJ9" + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0" + "." + A36[:30],
    }[kind]


class Env:
    """A throwaway HOME, vault and git config so tests never touch the user's own."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="git-redact-test-")
        self.vault = os.path.join(self.dir, "vault")
        self.env = dict(os.environ)
        self.env.update({
            "HOME": self.dir, "USERPROFILE": self.dir, "XDG_CONFIG_HOME": os.path.join(self.dir, "cfg"),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.path.join(self.dir, "gitconfig"),
            "GIT_REDACT_VAULT": self.vault, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
        })
        with open(self.env["GIT_CONFIG_GLOBAL"], "w") as f:
            f.write("[core]\n\tautocrlf = false\n[init]\n\tdefaultBranch = main\n")

    def run(self, args, cwd, check=True, input=None):
        r = subprocess.run(args, cwd=cwd, env=self.env, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check and r.returncode != 0:
            raise AssertionError("%s failed (%d):\n%s\n%s" % (args, r.returncode, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace")))
        return r

    def git(self, cwd, *args, **kw):
        return self.run(["git"] + list(args), cwd, **kw)

    def redact(self, cwd, *args, **kw):
        return self.run([sys.executable, SCRIPT] + list(args), cwd, **kw)

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def red(vault_dir=None, **kw):
    return gr.Redactor(root=None, vault=gr.Vault(vault_dir), load_config=False, **kw)


# ------------------------------------------------------------------------------------- rules
class RuleTests(unittest.TestCase):
    def test_every_builtin_sample_is_caught_and_restored(self):
        vdir = tempfile.mkdtemp()
        try:
            r = red(vdir)
            for kind in ["github-token", "gitlab-token", "slack-token", "discord-bot-token", "telegram-bot-token",
                         "aws-access-key-id", "google-api-key", "stripe-key", "openai-key", "npm-token", "sendgrid-key", "jwt"]:
                secret = fake(kind)
                text = 'const x = foo("%s");\n' % secret
                out, spans = r.clean_text(text)
                self.assertNotIn(secret, out, kind)
                self.assertTrue(spans and spans[0][2] == kind, "%s detected as %s" % (kind, spans))
                self.assertEqual(r.smudge_text(out), text, kind)
        finally:
            shutil.rmtree(vdir)

    def test_contextual_rules(self):
        r = red()
        cases = {
            "discord-webhook": "https://discord.com/api/webhooks/123456789012345678/" + A36 + A36[:20],
            "slack-webhook": "https://hooks.slack.com/services/T0ABC123/B0DEF456/" + A36[:24],
            "url-password": "postgres://app:s3cr3tP4ss@db.internal:5432/app",
            "secret-assignment": 'DB_PASSWORD = "Tr0ub4dor&3xyz"',
            "secret-line": "api_key: 9f8e7d6c5b4a39281706",
            "aws-secret-key": "aws_secret_access_key = " + (A36 + "abcd")[:40],
        }
        more = [
            ("secret-assignment", 'const secretHex = "9f86d081884c7d659a2feaa0c55ad015"'),
            ("secret-assignment", 'WEBHOOK_URL = "https://hooks.acme.io/in/' + A36 + '"'),
            ("secret-assignment", 'password = "SuperSecretPassword"'),
            ("url-password", "REDIS = redis://:s3cretPw9@cache:6379/0"),
        ]
        for rule, text in list(cases.items()) + more:
            out, spans = r.clean_text(text + "\n")
            self.assertEqual([s[2] for s in spans], [rule], text)
            self.assertIn("REDACTED", out)

    def test_private_key_body(self):
        body = "\n" + "\n".join([A36 * 2] * 5) + "\n"
        text = "-----BEGIN RSA PRIVATE KEY-----" + body + "-----END RSA PRIVATE KEY-----\n"
        out, spans = red().clean_text(text)
        self.assertEqual(spans[0][2], "private-key")
        self.assertIn("-----BEGIN RSA PRIVATE KEY-----REDACTED-----END RSA PRIVATE KEY-----", out)

    def test_code_and_placeholders_are_left_alone(self):
        r = red()
        for text in [
            "apiKey = config.apiKey",
            "token = accessToken",
            "password = user.password",
            "const API_KEY = process.env.API_KEY;",
            "token = os.environ['TOKEN']",
            "password: ${DB_PASSWORD}",
            'password: "{{ vault_db_password }}"',
            '"password": "changeme"',
            'password = "your-password-here"',
            'type: "password"',
            "SECRET_KEY=<put-it-here>",
            "token: xxxxxxxxxxxx",
            "passwordField = document.getElementById('pw')",
            "postgres://user:${PASS}@host/db",
            "hashed_password = bcrypt.hash(password)",
            'TOKEN_URL = "https://discord.com/api/oauth2/token"',
            '"@aws-sdk/credential-providers": "^3.654.0",',
            '[Token(Token = "JOPJAPIKFHO")]',
            '[Token(Token = "0x4A5B6C7")]',
            'SECRET_NAME = "database_password_v2"',
            'URL_RE = re.compile(r"postgresql://([^:]+):([^@]+)@([^:]+)")',
        ]:
            out, spans = r.clean_text(text + "\n")
            self.assertEqual(spans, [], "false positive on: " + text)

    def test_idempotent(self):
        vdir = tempfile.mkdtemp()
        try:
            r = red(vdir)
            text = 'TOKEN = "%s"\nurl = "postgres://u:hunter22x@h/db"\napi_key: 9f8e7d6c5b4a39281706\n' % fake("github-token")
            once, _ = r.clean_text(text)
            twice, spans = r.clean_text(once)
            self.assertEqual(once, twice)
            self.assertEqual(spans, [])
        finally:
            shutil.rmtree(vdir)

    def test_no_vault_gives_bare_placeholder(self):
        out, _ = red(None).clean_text(fake("npm-token"))
        self.assertEqual(out, "REDACTED")
        self.assertEqual(red(None).smudge_text(out), "REDACTED")

    def test_same_secret_same_placeholder_and_unknown_id_kept(self):
        vdir = tempfile.mkdtemp()
        try:
            r = red(vdir)
            s = fake("stripe-key")
            out, _ = r.clean_text("%s and %s" % (s, s))
            a, b = out.split(" and ")
            self.assertEqual(a, b)
            self.assertEqual(red(vdir).smudge_text("REDACTED-000000000000"), "REDACTED-000000000000")
            # a new process with the same vault restores it; a different vault does not
            self.assertEqual(red(vdir).smudge_text(out), "%s and %s" % (s, s))
            other = tempfile.mkdtemp()
            try:
                self.assertEqual(red(other).smudge_text(out), out)
            finally:
                shutil.rmtree(other)
        finally:
            shutil.rmtree(vdir)

    def test_placeholder_does_not_leak_the_secret(self):
        vdir1, vdir2 = tempfile.mkdtemp(), tempfile.mkdtemp()
        try:
            s = fake("github-token")
            # ids are an HMAC under a per-vault random key: two vaults give unrelated ids
            self.assertNotEqual(red(vdir1).clean_text(s)[0], red(vdir2).clean_text(s)[0])
        finally:
            shutil.rmtree(vdir1)
            shutil.rmtree(vdir2)

    def test_binary_and_oversized_pass_through(self):
        r = red()
        blob = b"\x00\x01" + fake("github-token").encode()
        self.assertEqual(r.clean(blob), blob)
        r.max_bytes = 10
        big = fake("github-token").encode()
        self.assertEqual(r.clean(big), big)

    def test_non_utf8_bytes_survive(self):
        r = red()
        data = b"caf\xe9 " + fake("npm-token").encode() + b" \xff\xfe end"
        out = r.clean(data)
        self.assertTrue(out.startswith(b"caf\xe9 REDACTED"))
        self.assertTrue(out.endswith(b" \xff\xfe end"))


# ------------------------------------------------------------------------------------- git integration
class GitTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.repo = os.path.join(self.e.dir, "repo")
        os.makedirs(self.repo)
        self.e.git(self.repo, "init", "-q")

    def tearDown(self):
        self.e.close()

    def write(self, name, data):
        path = os.path.join(self.repo, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data.encode() if isinstance(data, str) else data)
        return path

    def read(self, name, repo=None):
        with open(os.path.join(repo or self.repo, name), "rb") as f:
            return f.read().decode()

    def committed(self, name, rev="HEAD"):
        return self.e.git(self.repo, "show", "%s:%s" % (rev, name)).stdout.decode()

    def test_full_cycle(self):
        token = fake("github-token")
        src = 'module.exports = {\n  token: "%s",\n  db: "postgres://app:Pa55w0rd123@localhost/app",\n};\n' % token
        self.write("config.js", src)
        self.e.redact(self.repo, "init")
        self.e.git(self.repo, "add", "-A")
        self.e.git(self.repo, "commit", "-qm", "c1")

        stored = self.committed("config.js")
        self.assertNotIn(token, stored)
        self.assertNotIn("Pa55w0rd123", stored)
        self.assertEqual(stored.count("REDACTED-"), 2)
        self.assertEqual(self.read("config.js"), src, "working tree must be untouched")
        self.assertEqual(self.e.git(self.repo, "status", "--porcelain").stdout, b"")

        # git diff runs the clean filter on the working file: an edit never shows the secret
        with open(os.path.join(self.repo, "config.js"), "a") as f:
            f.write("// edited\n")
        diff = self.e.git(self.repo, "diff").stdout.decode()
        self.assertIn("+// edited", diff)
        self.assertNotIn(token, diff)
        self.e.git(self.repo, "checkout", "--", "config.js")

        # checkout puts the real value back from the vault
        os.remove(os.path.join(self.repo, "config.js"))
        self.e.git(self.repo, "checkout", "--", "config.js")
        self.assertEqual(self.read("config.js"), src)
        self.e.git(self.repo, "reset", "-q", "--hard")
        self.assertEqual(self.read("config.js"), src)

        # a clone elsewhere (no filter configured, different vault) only sees placeholders
        clone = os.path.join(self.e.dir, "clone")
        self.e.git(self.e.dir, "clone", "-q", self.repo, clone)
        self.assertNotIn(token, self.read("config.js", clone))
        self.assertIn("REDACTED-", self.read("config.js", clone))

        self.assertEqual(self.e.redact(self.repo, "check").returncode, 0)
        self.assertEqual(self.e.redact(self.repo, "check", "--rev", "HEAD").returncode, 0)

    def test_process_and_single_file_modes_agree(self):
        text = "x = 1\n" * 40000 + 'SECRET_TOKEN = "Zq9x8W7v6U5t4S3r2Q1p"\n'  # > 64 KiB: several packets
        self.write("big.py", text)
        self.e.redact(self.repo, "init")
        self.e.git(self.repo, "add", "big.py")
        via_process = self.e.git(self.repo, "show", ":big.py").stdout
        self.e.git(self.repo, "config", "--unset", "filter.redact.process")
        self.e.git(self.repo, "rm", "-q", "--cached", "big.py")
        self.e.git(self.repo, "add", "big.py")
        via_clean = self.e.git(self.repo, "show", ":big.py").stdout
        self.assertEqual(via_process, via_clean)
        self.assertNotIn(b"Zq9x8W7v6U5t4S3r2Q1p", via_process)
        self.assertEqual(len(via_process), len(text.encode()) - len("Zq9x8W7v6U5t4S3r2Q1p") + len("REDACTED-") + 12)

    def test_check_catches_uncovered_files(self):
        self.e.redact(self.repo, "init", "*.js")
        self.write("notes.txt", "stripe: %s\n" % fake("stripe-key"))
        self.write("app.js", "const k = '%s';\n" % fake("stripe-key"))
        self.e.git(self.repo, "add", "-A")
        r = self.e.redact(self.repo, "check", check=False)
        self.assertEqual(r.returncode, 1)
        out = r.stdout.decode()
        self.assertIn("notes.txt:1: stripe-key", out)
        self.assertNotIn("app.js", out)
        self.assertNotIn(fake("stripe-key"), out + r.stderr.decode(), "check must not print the secret")

    def test_hook_blocks_commit(self):
        self.e.redact(self.repo, "init", "*.js")
        self.e.redact(self.repo, "hook")
        self.write("leak.txt", "token=%s\n" % fake("npm-token"))
        self.e.git(self.repo, "add", "-A")
        r = self.e.git(self.repo, "commit", "-qm", "x", check=False)
        self.assertNotEqual(r.returncode, 0)

    def test_env_file_values_and_gitredact_file(self):
        self.write(".env", "NODE_ENV=production\nSTRIPE_WEBHOOK_SECRET=whsec_Q2w3E4r5T6y7U8i9\nPORT=3000\n")
        self.write(".gitignore", ".env\n")
        self.write(".gitredact", "rule internal-id \\bINT-[0-9]{6}\\b\nallow 9f8e7d6c5b4a39281706\ndisable jwt\n")
        jwt = fake("jwt")
        self.write("app.py", 'hook = "whsec_Q2w3E4r5T6y7U8i9"\nmode = "production"\nref = "INT-123456"\napi_key: 9f8e7d6c5b4a39281706\nj = "%s"\n' % jwt)
        self.e.redact(self.repo, "init")
        self.e.git(self.repo, "config", "--add", "redact.envFile", ".env")
        self.e.git(self.repo, "add", "-A")
        self.e.git(self.repo, "commit", "-qm", "c")
        stored = self.committed("app.py")
        self.assertNotIn("whsec_Q2w3E4r5T6y7U8i9", stored)
        self.assertIn('mode = "production"', stored, "non-secret env values must stay")
        self.assertNotIn("INT-123456", stored)
        self.assertIn("9f8e7d6c5b4a39281706", stored, "allow-listed value must stay")
        self.assertIn(jwt, stored, "disabled rule must not fire")

    def test_binary_file_untouched(self):
        data = b"\x89PNG\r\n\x1a\n\x00\x00" + fake("github-token").encode() + bytes(range(256))
        self.write("img.png", data)
        self.e.redact(self.repo, "init")
        self.e.git(self.repo, "add", "-A")
        self.assertEqual(self.e.git(self.repo, "show", ":img.png").stdout, data)

    def test_rules_and_diff_commands(self):
        self.write("a.js", "const k = '%s';\n" % fake("npm-token"))
        self.e.redact(self.repo, "init", "*.py")
        rules = self.e.redact(self.repo, "rules").stdout.decode("ascii")  # plain ASCII on every console
        self.assertIn("github-token", rules)
        diff = self.e.redact(self.repo, "diff").stdout.decode("ascii")
        self.assertIn("a.js:1: npm-token", diff)
        self.assertIn("NOT covered", diff)
        self.assertNotIn(fake("npm-token"), diff)

    def test_ignore_globs_skip_check(self):
        self.write("tests/fixtures/keys.txt", "k=%s\n" % fake("npm-token"))
        self.write("src/app.txt", "k=%s\n" % fake("npm-token"))
        self.write(".gitredact", "ignore tests/\n")
        self.e.git(self.repo, "add", "-A")
        out = self.e.redact(self.repo, "check", check=False).stdout.decode()
        self.assertIn("src/app.txt", out)
        self.assertNotIn("tests/fixtures", out)

    def test_init_is_idempotent(self):
        self.e.redact(self.repo, "init", "*.js", "*.py")
        self.e.redact(self.repo, "init", "*.js")
        attrs = self.read(".gitattributes")
        self.assertEqual(attrs.count("*.js filter=redact"), 1)
        self.assertEqual(attrs.count("*.py filter=redact"), 1)


if __name__ == "__main__":
    unittest.main()
