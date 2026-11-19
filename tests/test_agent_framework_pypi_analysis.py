"""Check the PyPI Analysis. Set BIGFIX_QNA to also run inert fixture checks."""
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from xml.etree import ElementTree

CONTENT = Path(__file__).resolve().parents[1] / "Fixlets/Universal/6 Microsoft_Agent_Framework_PyPI_Compromise.bes"


class AgentFrameworkAnalysisTest(unittest.TestCase):
    def test_content_contract(self):
        raw = CONTENT.read_bytes()
        raw.decode("utf-8")
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(raw.count(b"\r\n"), raw.count(b"\r"))
        self.assertEqual(raw.count(b"\r\n"), raw.count(b"\n"))
        analysis = ElementTree.fromstring(raw).find("Analysis")
        self.assertIsNotNone(analysis)
        self.assertEqual(len(analysis.findall("Property")), 1)
        self.assertEqual(analysis.find("Property").attrib, {
            "Name": "IOC Found-", "ID": "1", "EvaluationPeriod": "PT6H",
        })
        self.assertIsNone(analysis.find("ActionScript"))

    @unittest.skipUnless(os.environ.get("BIGFIX_QNA"), "BIGFIX_QNA is not configured")
    def test_fixture_results(self):
        query = " ".join(ElementTree.parse(CONTENT).findtext("Analysis/Property").split())
        if os.name == "nt":
            platform = "windows"
            layout = "Python399887/Lib/site-packages"
        elif sys.platform == "darwin":
            platform = "mac"
            layout = "Library/Python/3.99887/site-packages"
        else:
            platform = "linux"
            layout = "usr/local/lib/python3.99887/site-packages"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            query = query.replace("parent folder of windows folder", f'folder "{root}"') if platform == "windows" else query.replace('"/', f'"{root}/')
            package = root / layout / "agent_framework-1.26.2.dist-info"
            package.mkdir(parents=True)
            metadata = package / "METADATA"
            self.assertEqual(self.evaluate(query), "FALSE")
            metadata.write_text("Name: agent-framework\nVersion: 1.26.2\n", encoding="ascii")
            result = self.evaluate(query)
            self.assertTrue(result.startswith("TRUE - "))
            self.assertIn("METADATA", result)
            metadata.write_text("Name: agent-framework-core\nVersion: 1.26.2\n", encoding="ascii")
            self.assertEqual(self.evaluate(query), "FALSE")

    @staticmethod
    def evaluate(query):
        result = subprocess.run(
            [os.environ["BIGFIX_QNA"]], input=query + "\n", text=True,
            capture_output=True, check=True, timeout=30,
        )
        for line in result.stdout.splitlines():
            if "A: " in line:
                return line.split("A: ", 1)[1]
        raise AssertionError(result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
