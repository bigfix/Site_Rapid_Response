/* Console JScript compatible: no JSON dependency, eval, credentials or target selection. */
var PhpScan = (function () {
    function parameters(values) {
        var fields = phpScanFields, selected = {}, index, field, text, number, multiplier, minimum, maximum;
        for (index = 0; index < fields.length; index++) {
            field = fields[index];
            text = String(values[field.key]);
            if (field.text) {
                // Encode UTF-8 bytes, never interpolate a directory into script code.
                if (/[\x00-\x1f\x7f]/.test(text)) { throw new Error('Exclusions cannot contain control characters.'); }
                var entries = text.split(','), clean = [], j, entry, encoded, hex = 'x', k, byte;
                for (j = 0; j < entries.length; j++) {
                    entry = entries[j].replace(/^\s+|\s+$/g, '');
                    if (!entry) { continue; }
                    var prefix = phpScanWindows ? /^([A-Za-z]:[\\\/]|\*[\\\/])/ : /^(\/|\*\/)/;
                    var relative = phpScanWindows ? /(^|[\\\/])\.{1,2}([\\\/]|$)/ : /(^|\/)\.{1,2}(\/|$)/;
                    if (!prefix.test(entry) || relative.test(entry)) {
                        throw new Error('Use absolute exclusion paths or a leading */; . and .. segments are not allowed.');
                    }
                    clean.push(entry);
                }
                if (clean.length > 32) { throw new Error('Use at most 32 directory exclusions.'); }
                encoded = encodeURIComponent(clean.join(','));
                for (k = 0; k < encoded.length; k++) {
                    if (encoded.charAt(k) === '%') { byte = encoded.substr(k + 1, 2); k += 2; }
                    else { byte = encoded.charCodeAt(k).toString(16); if (byte.length < 2) { byte = '0' + byte; } }
                    hex += byte.toLowerCase();
                }
                if (hex.length > 8193) { throw new Error('Directory exclusions must fit within 4096 UTF-8 bytes.'); }
                selected[field.key] = hex;
                continue;
            }
            if (!/^[0-9]{1,9}$/.test(text)) { throw new Error(field.label + ': enter a whole number.'); }
            number = Number(text);
            multiplier = field.multiplier || 1;
            minimum = Math.ceil(field.min / multiplier);
            maximum = Math.floor(field.max / multiplier);
            if (number < minimum || number > maximum) { throw new Error(field.label + ': use ' + minimum + ' to ' + maximum + '.'); }
            number = number * multiplier;
            selected[field.key] = String(number);
        }
        return selected;
    }
    function prepare() {
        try {
            var values = {}, index, field;
            for (index = 0; index < phpScanFields.length; index++) {
                field = phpScanFields[index];
                values[field.key] = field.checkbox ? (document.getElementById(field.key).checked ? '1' : '0') : document.getElementById(field.key).value;
            }
            var selected = parameters(values);
            if (typeof TakeSecureFixletAction === 'undefined' || typeof Relevance === 'undefined') {
                throw new Error('Open this content in the BigFix Console to use this settings form. API/WebUI launches use defaults unless action parameters are supplied.');
            }
            // These are ordinary, nonsecret action parameters. The Console
            // obtains the current Task's Action1; no XML or script is rebuilt.
            TakeSecureFixletAction(Relevance('id of current fixlet'), Relevance('id of current bes site'), 'Action1', selected, {});
        } catch (error) { alert('Cannot prepare scan. ' + error.message); }
        return false;
    }
    return {parameters: parameters, prepare: prepare};
}());
document.body.ontakeaction = function () { return PhpScan.prepare(); };
