import { ICAO_COUNTRIES } from './icao-countries.js';

const FORMAT_LAYOUTS = {
    TD3: { lineCount: 2, lineLength: 44 },
    TD2: { lineCount: 2, lineLength: 36 },
    TD1: { lineCount: 3, lineLength: 30 },
};

const ISSUER_ALIASES = {
    DEU: ['DEU', 'D<<'],
    GBR: ['GBR', 'GBD', 'GBN', 'GBO', 'GBP', 'GBS'],
};
const KNOWN_ISSUER_CODES = new Set([
    ...ICAO_COUNTRIES.map(([, code]) => code),
    ...Object.values(ISSUER_ALIASES).flat(),
]);

function getMrzCharacterValue(character) {
    if (character >= '0' && character <= '9') return character.charCodeAt(0) - 48;
    if (character >= 'A' && character <= 'Z') return character.charCodeAt(0) - 55;
    if (character === '<') return 0;
    throw new Error(`Invalid MRZ character: ${character}`);
}

export function calculateMrzCheckDigit(value) {
    const weights = [7, 3, 1];
    let total = 0;
    for (let index = 0; index < value.length; index++) {
        total += getMrzCharacterValue(value[index]) * weights[index % weights.length];
    }
    return String(total % 10);
}

function checkDigitMatches(value, checkDigit) {
    return /^\d$/.test(checkDigit) && calculateMrzCheckDigit(value) === checkDigit;
}

function normalizeLetters(value) {
    return value.replace(/[0158]/g, (character) => ({
        0: 'O',
        1: 'I',
        5: 'S',
        8: 'B',
    })[character]);
}

function normalizeDigits(value) {
    return value.replace(/[ODQILSBZ]/g, (character) => ({
        O: '0',
        D: '0',
        Q: '0',
        I: '1',
        L: '1',
        S: '5',
        B: '8',
        Z: '2',
    })[character]);
}

function replaceField(line, start, end, normalize) {
    return line.slice(0, start) + normalize(line.slice(start, end)) + line.slice(end);
}

function repairNameFillerTail(line, fieldStart, expectedLength = line.length) {
    const nameSeparator = line.indexOf('<<', fieldStart);
    if (nameSeparator < 0) return line;
    const fillerSeparator = line.indexOf('<<', nameSeparator + 2);
    if (fillerSeparator < 0 || fillerSeparator >= expectedLength) return line;
    return line.slice(0, fillerSeparator)
        + '<'.repeat(expectedLength - fillerSeparator);
}

function repairPassportPrefix(line) {
    if (!line.startsWith('PC')) return line;
    const issuer = normalizeLetters(line.slice(2, 5));
    return KNOWN_ISSUER_CODES.has(issuer) ? `P<${line.slice(2)}` : line;
}

function normalizePassportNameLine(line, expectedLength) {
    if (!line.startsWith('P')) return null;

    for (const issuerStart of [2, 1]) {
        const issuer = normalizeLetters(line.slice(issuerStart, issuerStart + 3));
        if (!KNOWN_ISSUER_CODES.has(issuer)) continue;

        const nameStart = issuerStart + 3;
        let normalized = `P<${issuer}${line.slice(nameStart)}`;
        normalized = repairNameFillerTail(normalized, 5, expectedLength);
        return normalized.slice(0, expectedLength).padEnd(expectedLength, '<');
    }

    return null;
}

export function repairMrzFillerTails(lines, format) {
    const repaired = [...lines];
    if (format === 'TD3' || format === 'TD2') {
        const lineLength = FORMAT_LAYOUTS[format].lineLength;
        repaired[0] = normalizePassportNameLine(repaired[0], lineLength)
            || repairNameFillerTail(repairPassportPrefix(repaired[0]), 5, lineLength);
    } else if (format === 'TD1') {
        repaired[2] = repairNameFillerTail(
            repaired[2],
            0,
            FORMAT_LAYOUTS.TD1.lineLength
        );
    }
    return repaired;
}

function normalizeCandidateLine(line, format, index, lineLength) {
    let normalized = line;
    const isPassportNameLine =
        (format === 'TD3' || format === 'TD2') && index === 0;
    const isIdCardNameLine = format === 'TD1' && index === 2;

    if (isPassportNameLine) {
        const passportNameLine = normalizePassportNameLine(normalized, lineLength);
        if (passportNameLine) {
            normalized = passportNameLine;
        } else if (normalized.startsWith('P')) {
            normalized = repairNameFillerTail(
                repairPassportPrefix(normalized),
                5,
                lineLength
            );
        }
    }
    if (isIdCardNameLine) {
        normalized = repairNameFillerTail(normalized, 0, lineLength);
    }
    if (format === 'TD3' && index === 1) {
        normalized = normalizeTd3Line2(normalized);
    }

    if (
        normalized.length > lineLength &&
        normalized.length <= lineLength + 8 &&
        /^[<KCLSI1E]+$/.test(normalized.slice(lineLength))
    ) {
        normalized = normalized.slice(0, lineLength);
    } else if (
        normalized.length < lineLength &&
        normalized.length >= lineLength - 8 &&
        (isIdCardNameLine || (isPassportNameLine && normalized.startsWith('P'))) &&
        /^[A-Z0-9<]+$/.test(normalized)
    ) {
        normalized += '<'.repeat(lineLength - normalized.length);
    }

    return normalized.length === lineLength && /^[A-Z0-9<]+$/.test(normalized)
        ? normalized
        : null;
}

function normalizeCandidateFields(lines, format) {
    const normalized = repairMrzFillerTails(lines, format);
    normalized[0] = replaceField(normalized[0], 0, 1, normalizeLetters);
    if (format === 'TD3' || format === 'TD2') {
        normalized[0] = replaceField(normalized[0], 2, 5, normalizeLetters);
        normalized[0] = replaceField(
            normalized[0],
            5,
            normalized[0].length,
            normalizeLetters
        );
        normalized[1] = replaceField(normalized[1], 10, 13, normalizeLetters);
    } else {
        normalized[0] = replaceField(normalized[0], 2, 5, normalizeLetters);
        normalized[1] = replaceField(normalized[1], 15, 18, normalizeLetters);
        normalized[2] = replaceField(normalized[2], 0, normalized[2].length, normalizeLetters);
    }

    const digitRanges = format === 'TD3'
        ? [[9, 10], [13, 20], [21, 28], [42, 44]]
        : format === 'TD2'
            ? [[9, 10], [13, 20], [21, 28], [35, 36]]
            : [[14, 15]];
    for (const [start, end] of digitRanges) {
        normalized[format === 'TD1' ? 0 : 1] = replaceField(
            normalized[format === 'TD1' ? 0 : 1],
            start,
            end,
            normalizeDigits
        );
    }
    if (format === 'TD1') {
        for (const [start, end] of [[0, 7], [8, 15], [29, 30]]) {
            normalized[1] = replaceField(normalized[1], start, end, normalizeDigits);
        }
    }
    return normalized;
}

function getAnchoredFillerTailRange(value) {
    const trailingRun = /[<KCLSI1E]+$/.exec(value);
    if (!trailingRun || !trailingRun[0].includes('<')) return null;
    const firstFiller = trailingRun[0].indexOf('<');
    return [trailingRun.index + firstFiller, value.length];
}

function getFillerCorrectionRanges(value, offset = 0) {
    if (/^[<KCLSI1E]+$/.test(value)) {
        return [[offset, offset + value.length]];
    }

    const trailingRun = /[<KCLSI1E]+$/.exec(value);
    if (!trailingRun || !trailingRun[0].includes('<')) return [];
    return [[offset + trailingRun.index, offset + value.length]];
}

function repairAnchoredFillerTail(value) {
    const anchoredRange = getAnchoredFillerTailRange(value);
    if (!anchoredRange) return value;
    return replaceField(value, anchoredRange[0], anchoredRange[1], (tail) => (
        tail.replace(/[KCLSI1E]/g, '<')
    ));
}

function alignTd3FixedFields(line) {
    for (let documentNumberLength = 9; documentNumberLength >= 1; documentNumberLength--) {
        const documentCheckDigit = normalizeDigits(line[documentNumberLength] || '');
        if (!/^\d$/.test(documentCheckDigit)) continue;

        const nationalityStart = documentNumberLength + 1;
        const nationality = line.slice(nationalityStart, nationalityStart + 3);
        if (!/^[A-Z]{3}$/.test(normalizeLetters(nationality))) continue;

        const birthDateStart = nationalityStart + 3;
        const birthDate = normalizeDigits(line.slice(birthDateStart, birthDateStart + 6));
        const birthDateCheckDigit = normalizeDigits(line[birthDateStart + 6] || '');
        if (
            !/^\d{6}$/.test(birthDate) ||
            !checkDigitMatches(birthDate, birthDateCheckDigit)
        ) {
            continue;
        }

        const sexMarker = line[birthDateStart + 7];
        if (!'MFX<'.includes(sexMarker)) continue;
        const expiryDateStart = birthDateStart + 8;
        const expiryDate = normalizeDigits(line.slice(expiryDateStart, expiryDateStart + 6));
        const expiryDateCheckDigit = normalizeDigits(line[expiryDateStart + 6] || '');
        if (
            !/^\d{6}$/.test(expiryDate) ||
            !checkDigitMatches(expiryDate, expiryDateCheckDigit)
        ) {
            continue;
        }

        const optionalDataStart = expiryDateStart + 7;
        if (line.length < optionalDataStart + 2) continue;
        const documentNumber = normalizeAlphanumericForCheckDigit(
            line.slice(0, documentNumberLength).padEnd(9, '<'),
            documentCheckDigit
        );
        if (!documentNumber) continue;

        return documentNumber
            + documentCheckDigit
            + nationality
            + line.slice(birthDateStart, birthDateStart + 7)
            + sexMarker
            + line.slice(expiryDateStart, expiryDateStart + 7)
            + line.slice(optionalDataStart);
    }

    return line;
}

function normalizeTd3Line2(line) {
    const optionalDataStart = 28;
    const optionalDataLength = 14;
    line = alignTd3FixedFields(line);
    if (line.length < optionalDataStart + 2) return line;

    const fixedFields = line.slice(0, optionalDataStart);
    const tail = line.slice(optionalDataStart);
    let optionalData = tail.slice(0, -2);
    const checkDigits = tail.slice(-2);

    if (optionalData.length > optionalDataLength) {
        const overflow = optionalData.slice(optionalDataLength);
        if (!/^[<KCLSI1E]+$/.test(overflow)) return line;
        optionalData = optionalData.slice(0, optionalDataLength);
    } else {
        optionalData = optionalData.padEnd(optionalDataLength, '<');
    }

    optionalData = repairAnchoredFillerTail(optionalData);
    return fixedFields + optionalData + checkDigits;
}

function normalizeAlphanumericForCheckDigit(
    value,
    checkDigit,
    eligibleRanges,
    fillerRanges = []
) {
    if (!/^\d$/.test(checkDigit)) return null;
    if (checkDigitMatches(value, checkDigit)) return value;

    const ranges = eligibleRanges || [[0, value.length]];
    const alternatives = {
        O: ['O', '0'],
        0: ['0', 'O'],
        I: ['I', '1'],
        1: ['1', 'I'],
        S: ['S', '5'],
        5: ['5', 'S'],
        B: ['B', '8'],
        8: ['8', 'B'],
        Z: ['Z', '2'],
        2: ['2', 'Z'],
    };
    const memo = Array.from({ length: value.length }, () => new Map());

    function findMatch(index, sum) {
        if (index === value.length) {
            return sum === Number(checkDigit) ? '' : null;
        }
        if (memo[index].has(sum)) return memo[index].get(sum);

        const character = value[index];
        const canSwap = ranges.some(([start, end]) => index >= start && index < end);
        const canRepairFiller = fillerRanges.some(
            ([start, end]) => index >= start && index < end
        );
        const choices = canSwap ? [...(alternatives[character] || [character])] : [character];
        if (canRepairFiller && /[KCLSI1E]/.test(character)) choices.push('<');
        for (const choice of choices) {
            const nextSum = (
                sum + getMrzCharacterValue(choice) * [7, 3, 1][index % 3]
            ) % 10;
            const suffix = findMatch(index + 1, nextSum);
            if (suffix !== null) {
                const match = choice + suffix;
                memo[index].set(sum, match);
                return match;
            }
        }
        memo[index].set(sum, null);
        return null;
    }

    return findMatch(0, 0);
}

function dateToIso(date) {
    return `${String(date.getFullYear()).padStart(4, '0')}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
}

function resolveMrzDate(value, dateType, today) {
    if (!/^\d{6}$/.test(value)) return { error: 'invalid-date' };

    const currentYear = today.getFullYear();
    const twoDigitYear = Number(value.slice(0, 2));
    const maximumPlausibleExpiryYears = 30;
    let year = Math.floor(currentYear / 100) * 100 + twoDigitYear;
    if (dateType === 'birth') {
        if (year > currentYear) year -= 100;
    } else {
        if (year > currentYear + maximumPlausibleExpiryYears) year -= 100;
    }

    const month = Number(value.slice(2, 4));
    const day = Number(value.slice(4, 6));
    const date = new Date(year, month - 1, day);
    if (
        date.getFullYear() !== year ||
        date.getMonth() !== month - 1 ||
        date.getDate() !== day
    ) {
        return { error: 'invalid-date' };
    }

    const isoDate = dateToIso(date);
    if (dateType === 'birth' && isoDate > dateToIso(today)) {
        return { error: 'invalid-date' };
    }
    if (dateType === 'expiry' && isoDate < dateToIso(today)) {
        return { error: 'expired' };
    }
    return { value: isoDate };
}

function getLayouts(documentType) {
    if (documentType === 'passport') return ['TD3', 'TD2'];
    if (documentType === 'id-card') return ['TD1'];
    return [];
}

function collectCandidates(lines, format) {
    const { lineCount, lineLength } = FORMAT_LAYOUTS[format];
    const candidates = [];
    const candidateKeys = new Set();
    const normalizeCandidate = (candidate) => {
        const normalized = candidate.map((line, index) => (
            normalizeCandidateLine(line, format, index, lineLength)
        ));
        return normalized.every(Boolean) ? normalized : null;
    };
    const addCandidate = (candidate) => {
        const normalized = normalizeCandidate(candidate);
        if (normalized) {
            const key = normalized.join('\n');
            if (!candidateKeys.has(key)) {
                candidateKeys.add(key);
                candidates.push(normalized);
            }
        }
    };

    for (let start = 0; start <= lines.length - lineCount; start++) {
        addCandidate(lines.slice(start, start + lineCount));
    }

    const totalLength = lineCount * lineLength;
    for (let start = 0; start < lines.length; start++) {
        let combined = '';
        for (let end = start; end < lines.length; end++) {
            const line = lines[end];
            if (!/^[A-Z0-9<]+$/.test(line)) break;
            combined += line;
            if (combined.length === totalLength) {
                const candidate = [];
                for (let offset = 0; offset < totalLength; offset += lineLength) {
                    candidate.push(combined.slice(offset, offset + lineLength));
                }
                addCandidate(candidate);
                break;
            }
            if (combined.length > totalLength) break;
        }
    }
    return candidates;
}

function validateCandidate(lines, format, selectedCountry, today) {
    const normalizedLines = normalizeCandidateFields(lines, format);
    const line1 = normalizedLines[0];
    const line2 = normalizedLines[1];
    if (format === 'TD3' && line1[0] !== 'P') {
        return { ok: false, error: 'invalid-document-type' };
    }
    if (format === 'TD1' && line1[0] !== 'I') {
        return { ok: false, error: 'invalid-document-type' };
    }

    const issuer = line1.slice(2, 5);
    const expectedIssuers = ISSUER_ALIASES[selectedCountry] || [selectedCountry];
    if (!expectedIssuers.includes(issuer)) {
        return { ok: false, error: 'country-mismatch' };
    }

    let documentNumber;
    let documentNumberCheckDigit;
    let birthDateValue;
    let birthDateCheckDigit;
    let expiryDateValue;
    let expiryDateCheckDigit;
    let compositeCheckDigit;
    let optionalData = '';
    let optionalDataCheckDigit = '';
    let secondOptionalData = '';

    if (format === 'TD3') {
        documentNumber = line2.slice(0, 9);
        documentNumberCheckDigit = line2[9];
        birthDateValue = line2.slice(13, 19);
        birthDateCheckDigit = line2[19];
        expiryDateValue = line2.slice(21, 27);
        expiryDateCheckDigit = line2[27];
        optionalData = line2.slice(28, 42);
        optionalDataCheckDigit = line2[42];
        compositeCheckDigit = line2[43];
    } else if (format === 'TD2') {
        documentNumber = line2.slice(0, 9);
        documentNumberCheckDigit = line2[9];
        birthDateValue = line2.slice(13, 19);
        birthDateCheckDigit = line2[19];
        expiryDateValue = line2.slice(21, 27);
        expiryDateCheckDigit = line2[27];
        optionalData = line2.slice(28, 35);
        compositeCheckDigit = line2[35];
    } else {
        documentNumber = line1.slice(5, 14);
        documentNumberCheckDigit = line1[14];
        birthDateValue = line2.slice(0, 6);
        birthDateCheckDigit = line2[6];
        expiryDateValue = line2.slice(8, 14);
        expiryDateCheckDigit = line2[14];
        optionalData = line1.slice(15, 30);
        secondOptionalData = normalizedLines[1].slice(18, 29);
        compositeCheckDigit = line2[29];
    }

    documentNumber = normalizeAlphanumericForCheckDigit(
        documentNumber,
        documentNumberCheckDigit
    );
    if (!documentNumber) return { ok: false, error: 'invalid-check-digit' };

    if (format === 'TD3') {
        if (optionalDataCheckDigit === '<') {
            if (!/^[<KCLSI1E]+$/.test(optionalData)) {
                return { ok: false, error: 'invalid-check-digit' };
            }
            optionalData = optionalData.replace(/[KCLSI1E]/g, '<');
        } else {
            const fillerRanges = getFillerCorrectionRanges(optionalData);
            optionalData = repairAnchoredFillerTail(optionalData);
            optionalData = normalizeAlphanumericForCheckDigit(
                optionalData,
                optionalDataCheckDigit,
                undefined,
                fillerRanges
            );
            if (!optionalData) return { ok: false, error: 'invalid-check-digit' };
        }
    }

    const sexMarker = format === 'TD1' ? line2[7] : line2[20];
    if (!'MFX<'.includes(sexMarker)) {
        return { ok: false, error: 'invalid-document-type' };
    }
    if (!/[A-Z0-9]/.test(documentNumber)) {
        return { ok: false, error: 'invalid-document-number' };
    }
    if (
        !checkDigitMatches(birthDateValue, birthDateCheckDigit) ||
        !checkDigitMatches(expiryDateValue, expiryDateCheckDigit)
    ) {
        return { ok: false, error: 'invalid-check-digit' };
    }

    let compositeValue;
    let compositeAmbiguousRanges;
    let compositeFillerRanges = [];
    if (format === 'TD3') {
        compositeValue = documentNumber
            + documentNumberCheckDigit
            + birthDateValue
            + birthDateCheckDigit
            + line2.slice(21, 28)
            + optionalData
            + optionalDataCheckDigit;
        compositeAmbiguousRanges = [];
    } else if (format === 'TD2') {
        compositeFillerRanges = getFillerCorrectionRanges(optionalData, 24);
        optionalData = repairAnchoredFillerTail(optionalData);
        compositeValue = documentNumber
            + documentNumberCheckDigit
            + birthDateValue
            + birthDateCheckDigit
            + line2.slice(21, 28)
            + optionalData;
        compositeAmbiguousRanges = [[24, 31]];
    } else {
        compositeFillerRanges = [
            ...getFillerCorrectionRanges(optionalData, 10),
            ...getFillerCorrectionRanges(secondOptionalData, 39),
        ];
        optionalData = repairAnchoredFillerTail(optionalData);
        secondOptionalData = repairAnchoredFillerTail(secondOptionalData);
        compositeValue = documentNumber
            + documentNumberCheckDigit
            + optionalData
            + birthDateValue
            + birthDateCheckDigit
            + normalizedLines[1].slice(8, 15)
            + secondOptionalData;
        compositeAmbiguousRanges = [[10, 25], [39, 50]];
    }
    const normalizedCompositeValue = normalizeAlphanumericForCheckDigit(
        compositeValue,
        compositeCheckDigit,
        compositeAmbiguousRanges,
        compositeFillerRanges
    );
    if (!normalizedCompositeValue) {
        return { ok: false, error: 'invalid-check-digit' };
    }

    const birthDate = resolveMrzDate(birthDateValue, 'birth', today);
    if (birthDate.error) return { ok: false, error: birthDate.error };
    const expiryDate = resolveMrzDate(expiryDateValue, 'expiry', today);
    if (expiryDate.error) return { ok: false, error: expiryDate.error };

    return {
        ok: true,
        format,
        issuingState: issuer,
        dateOfBirth: birthDate.value,
        expirationDate: expiryDate.value,
    };
}

export function parseMrzText(text, documentType, selectedCountry, today = new Date()) {
    const layouts = getLayouts(documentType);
    if (!layouts.length || !selectedCountry) {
        return { ok: false, error: 'invalid-selection' };
    }

    const lines = text.toUpperCase().split(/\r?\n/).map((line) => (
        line.replace(/\s+/g, '')
    )).filter(Boolean);
    const errors = [];
    for (const format of layouts) {
        for (const candidate of collectCandidates(lines, format)) {
            const result = validateCandidate(candidate, format, selectedCountry, today);
            if (result.ok) return result;
            errors.push(result.error);
        }
    }

    if (!errors.length) return { ok: false, error: 'mrz-not-found' };
    for (const preferredError of [
        'invalid-check-digit',
        'country-mismatch',
        'expired',
        'invalid-date',
        'invalid-document-type',
    ]) {
        if (errors.includes(preferredError)) return { ok: false, error: preferredError };
    }
    return { ok: false, error: errors[0] };
}
