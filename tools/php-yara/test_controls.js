/* Exact embedded form tests. Node.js is for maintainers, never endpoints. */
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
const root = path.resolve(__dirname, '../..');
const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'manifest.json'), 'utf8'));
let checks = 0;
for (const platform of ['Windows', 'Linux']) {
    const xml = fs.readFileSync(path.join(root, manifest.content[platform]), 'utf8');
    const description = xml.match(/<Description>([\s\S]*?)<\/Description>/)[1]
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'").replace(/&amp;/g, '&');
    const script = description.split('<script type="text/javascript">')[1].split('</script>')[0];
    const elements = {}, issued = [];
    const context = {document:{body:{},getElementById:id=>elements[id]}, JSON:undefined,
        TakeSecureFixletAction:(...args)=>issued.push(args),
        Relevance:query=>({'id of current fixlet':4321,'id of current bes site':1234})[query],
        alert:message=>{throw Error(message);}};
    vm.createContext(context);
    vm.runInContext(script, context);
    const values = {};
    for (const field of context.phpScanFields) {
        const value = field.text ? '' : String(field.default / (field.multiplier || 1));
        values[field.key] = value;
        elements[field.key] = {value, checked:false};
    }
    assert.equal(context.phpScanAction, undefined);
    assert(!script.includes('ImportXML') && !script.includes('createfile until'));
    assert.equal(elements.PHPEnumerationSeconds.value, '20');
    assert.equal(elements.PHPScanSeconds.value, '15');
    assert.equal(context.PhpScan.prepare(), false);
    assert.deepEqual(issued[0].slice(0, 3), [4321, 1234, 'Action1']);
    assert.equal(Object.keys(issued[0][4]).length, 0);
    const defaults = issued[0][3];
    for (const [key, value] of Object.entries({PHPEnumerationSeconds:'1200', PHPScanSeconds:'900',
        PHPIncludeBuildText:'0', PHPIncludeNonstandardNames:'0', PHPIncludeBroaderLocations:'0',
        PHPMaxFileMB:'512', PHPMaxFiles:'5000000', PHPExcludeDirectoriesHex:'x'})) {
        assert.equal(defaults[key], value); checks++;
    }
    for (const field of context.phpScanFields) {
        if (field.text) {
            const good = platform === 'Windows'
                ? ['C:\\data\\*', 'C:\\data\\', '*\\data\\*', 'C:\\Program Files\\PHP\\*, C:\\café[1]\\', 'C:\\$(whoami)&<>\\*']
                : ['/data/*', '/data/', '*/data/*', '/opt/PHP App/*, /opt/café[1]/', '/opt/$(whoami)&<>/*'];
            for (const value of good) {
                const clean = value.split(',').map(s=>s.trim()).filter(Boolean).join(',');
                assert.equal(context.PhpScan.parameters({...values,[field.key]:value})[field.key],
                    'x' + Buffer.from(clean).toString('hex')); checks++;
            }
            const base = platform === 'Windows' ? 'C:\\data\\' : '/data/';
            for (const value of ['relative/*', base + '../*', base + '\n*', base + '\0*',
                Array(34).join(base + '*, '), base + 'a'.repeat(4096)]) {
                assert.throws(()=>context.PhpScan.parameters({...values,[field.key]:value})); checks++;
            }
            continue;
        }
        const minimum = Math.ceil(field.min / (field.multiplier || 1));
        const maximum = Math.floor(field.max / (field.multiplier || 1));
        for (const value of ['', '1;whoami', '1\n', '1"/><ActionScript>', '-1', '1.5', '1000000000', String(minimum-1), String(maximum+1)]) {
            assert.throws(()=>context.PhpScan.parameters({...values,[field.key]:value})); checks++;
        }
        for (const value of [minimum, maximum]) {
            assert.equal(context.PhpScan.parameters({...values,[field.key]:String(value)})[field.key],
                String(value * (field.multiplier || 1))); checks++;
        }
    }
    elements.PHPEnumerationSeconds.value = '21'; elements.PHPScanSeconds.value = '16';
    elements.PHPExcludeDirectoriesHex.value = platform === 'Windows' ? 'C:\\PHP App\\*' : '/opt/PHP App/*';
    elements.PHPIncludeNonstandardNames.checked = true;
    assert.equal(context.document.body.ontakeaction(), false);
    assert.equal(issued[1][3].PHPEnumerationSeconds, '1260');
    assert.equal(issued[1][3].PHPScanSeconds, '960');
    assert.equal(issued[1][3].PHPIncludeNonstandardNames, '1');
    delete context.TakeSecureFixletAction;
    assert.throws(()=>context.PhpScan.prepare(), /BigFix Console/);
    assert.equal(issued.length, 2);
    checks += 12;
}
console.log(JSON.stringify({passed:true, platforms:2, checks, JSON_dependency:false}));
