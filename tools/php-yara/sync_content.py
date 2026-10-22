"""Check or refresh embedded sources without rebuilding native Task actions.

Run from any directory with Python 3.9+. Python is a maintainer tool only;
the Linux endpoint scanner has no Python dependency. Changes to the settings
bindings or ActionScript wrapper are made in the BES files and reviewed there.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
from xml.etree import ElementTree as ET

PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parents[1]
MANIFEST = json.loads((PACKAGE / 'manifest.json').read_text(encoding='utf-8'))
BLOCK = re.compile(
    r'createfile until (END_PHP_YARA_[a-f0-9]+)\n(.*?)\n\1'
    r'\ndelete "\{parameter "work"\}/([^"]+)"', re.S)


def synchronize(write=False):
    changed = []
    for platform, relative in MANIFEST['content'].items():
        path = ROOT / relative
        root = ET.parse(path).getroot()
        node = root[0]
        action = node.find('.//ActionScript')
        if action is None:
            continue
        replacements = []
        for match in BLOCK.finditer(action.text):
            name = match.group(3)
            if name not in MANIFEST['payloads']:
                raise ValueError('Unrecognized embedded payload: ' + name)
            source = (PACKAGE / name).read_text(encoding='utf-8')
            marker = 'END_PHP_YARA_' + hashlib.sha256(source.encode()).hexdigest()[:16]
            block = ('createfile until ' + marker + '\n' + source.removesuffix('\n').replace('{', '{{')
                     + '\n' + marker + '\ndelete "{parameter "work"}/' + name + '"')
            replacements.append((match.start(), match.end(), block))
        expected = 4 if platform == 'Windows' else 2
        if len(replacements) != expected:
            raise ValueError('Wrong embedded payload count for ' + platform)
        original_action = action.text
        for start, end, replacement in reversed(replacements):
            action.text = action.text[:start] + replacement + action.text[end:]
        description = node.find('Description')
        original_description = description.text
        prefix, javascript = original_description.split('/* Console JScript compatible:', 1)
        _, suffix = javascript.split('</script>', 1)
        description.text = prefix + (PACKAGE / 'scan-controls.js').read_text(encoding='utf-8') + '</script>' + suffix
        if action.text != original_action or description.text != original_description:
            changed.append(relative)
            if write:
                ET.indent(root, space='  ')
                ET.ElementTree(root).write(path, encoding='utf-8', xml_declaration=True)
    return changed


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='Refresh embedded sources in the BES files.')
    args = parser.parse_args()
    changed = synchronize(args.write)
    print(json.dumps({'synchronized': not changed or args.write, 'changed': changed}))
    raise SystemExit(0 if not changed or args.write else 1)
