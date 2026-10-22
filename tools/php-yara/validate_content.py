"""Offline checks for the portable bundle; does not launch an endpoint scan."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from xml.etree import ElementTree as ET

from sync_content import MANIFEST, PACKAGE, ROOT, BLOCK, synchronize


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema', type=Path, help='Optional BES.xsd; requires xmlschema installed in the maintainer environment.')
    args = parser.parse_args()
    assert not synchronize(), 'Run sync_content.py --write after editing sources.'
    schema = None
    if args.schema:
        import xmlschema
        schema = xmlschema.XMLSchema(str(args.schema))
    checks = {}
    for platform, relative in MANIFEST['content'].items():
        path = ROOT / relative
        if schema:
            schema.validate(str(path))
        node = ET.parse(path).getroot()[0]
        action = node.findtext('.//ActionScript')
        if action is None:
            properties = node.findall('Property')
            assert len(properties) == 4
            assert len({prop.attrib['ID'] for prop in properties}) == 4
            assert all(prop.attrib['EvaluationPeriod'] == 'PT5M' for prop in properties)
            assert all('summary.txt' in prop.text and 'scan.log' not in prop.text for prop in properties)
            checks[platform] = {'properties': 4}
            continue
        description = node.findtext('Description')
        script = description.split('<script type="text/javascript">', 1)[1].split('</script>', 1)[0]
        assert not any(token in script for token in ['phpScanAction', 'ImportXML', 'createfile until', 'begin prefetch block'])
        assert 'TakeSecureFixletAction' in script and "'Action1'" in script
        assert '"PHPMaxFileMB" = "512"' in action
        assert '"PHPMaxFiles" = "5000000"' in action
        assert 'parameter "scanExit" = "10"' in action
        count = 0
        for match in BLOCK.finditer(action):
            payload = match.group(2).replace('{{', '{') + '\n'
            source = (PACKAGE / match.group(3)).read_text(encoding='utf-8')
            assert payload == source.rstrip('\n') + '\n', match.group(3)
            count += 1
        if platform == 'Linux':
            executable_lines = '\n'.join(line for line in action.splitlines() if not line.lstrip().startswith('#'))
            assert not re.search(r'\bpython[0-9.]*\b', executable_lines, re.I)
        checks[platform] = {'exact_payloads': count, 'parameter_only_description': True}
    assert hashlib.sha256((PACKAGE / 'php-detect.yar').read_bytes()).hexdigest() == MANIFEST['rule_sha256']
    bash = shutil.which('bash')
    if bash:
        result = subprocess.run([bash, '-n'], shell=False,
                                input=(PACKAGE / 'scan-linux.sh').read_text(encoding='utf-8').encode('utf-8'),
                                timeout=20, capture_output=True)
        assert result.returncode == 0, result.stderr
    node = shutil.which('node')
    if not node:
        raise SystemExit('Node.js is needed for the maintainer form tests, not for endpoint scanning.')
    subprocess.run([node, str(PACKAGE / 'test_controls.js')], shell=False, timeout=30, check=True)
    print(json.dumps({'passed': True, 'schema_checked': schema is not None, 'bash_parser_checked': bool(bash), 'content': checks}))


if __name__ == '__main__':
    main()
