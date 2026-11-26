import test from 'node:test';
import assert from 'node:assert/strict';
import { ICAO_COUNTRIES } from '../public/icao-countries.js';
import {
    calculateMrzCheckDigit,
    parseMrzText,
    repairMrzFillerTails,
} from '../public/mrz.js';

const today = new Date(2026, 10, 20);

function check(value) {
    return calculateMrzCheckDigit(value);
}

function makeTd3({
    issuer = 'DEU',
    nationality = 'DEU',
    documentNumber = 'A12345678',
    dateOfBirth = '900101',
    expirationDate = '301231',
    optionalData = 'ZE184226B<<<<<',
    name = 'DOE<<JANE',
} = {}) {
    const line1 = `P<${issuer}${name}${'<'.repeat(44 - 5 - name.length)}`;
    let line2 = documentNumber
        + check(documentNumber)
        + nationality
        + dateOfBirth
        + check(dateOfBirth)
        + 'F'
        + expirationDate
        + check(expirationDate)
        + optionalData
        + check(optionalData);
    line2 += check(line2.slice(0, 10) + line2.slice(13, 20) + line2.slice(21, 43));
    return [line1, line2];
}

function makeTd2({
    issuer = 'GBN',
    nationality = 'GBR',
    documentNumber = 'A12345678',
    dateOfBirth = '900101',
    expirationDate = '301231',
    optionalData = 'ABC<<<<',
    name = 'DOE<<JANE',
} = {}) {
    const line1 = `P<${issuer}${name}${'<'.repeat(36 - 5 - name.length)}`;
    let line2 = documentNumber
        + check(documentNumber)
        + nationality
        + dateOfBirth
        + check(dateOfBirth)
        + 'F'
        + expirationDate
        + check(expirationDate)
        + optionalData;
    line2 += check(line2.slice(0, 10) + line2.slice(13, 20) + line2.slice(21, 35));
    return [line1, line2];
}

function makeTd1({
    documentCode = 'I',
    issuer = 'D<<',
    nationality = 'DEU',
    documentNumber = 'A12345678',
    dateOfBirth = '900101',
    expirationDate = '301231',
    optionalData = '<'.repeat(15),
    secondOptionalData = '<'.repeat(11),
    name = 'DOE<<JANE',
} = {}) {
    const numberField = documentNumber.slice(0, 9);
    const overflow = documentNumber.slice(9);
    const optionalField = overflow
        ? `${overflow}${check(documentNumber)}${optionalData}`
            .slice(0, 15)
            .padEnd(15, '<')
        : optionalData;
    const line1 = `${documentCode}<${issuer}${numberField}`
        + `${overflow ? '<' : check(documentNumber)}${optionalField}`;
    let line2 = dateOfBirth
        + check(dateOfBirth)
        + 'F'
        + expirationDate
        + check(expirationDate)
        + nationality
        + secondOptionalData;
    const compositeValue = line1.slice(5, 30)
        + line2.slice(0, 7)
        + line2.slice(8, 15)
        + line2.slice(18, 29);
    line2 += check(compositeValue);
    const line3 = `${name}${'<'.repeat(30 - name.length)}`;
    return [line1, line2, line3];
}

function replaceField(line, start, end, transform) {
    return line.slice(0, start) + transform(line.slice(start, end)) + line.slice(end);
}

function renderLetterAsDigit(value) {
    return value.replace(/[BOSI]/g, (character) => ({
        B: '8',
        O: '0',
        S: '5',
        I: '1',
    })[character]);
}

function renderDigitAsLetter(value) {
    const zeroVariants = ['O', 'D', 'Q'];
    const oneVariants = ['I', 'L'];
    let zeroIndex = 0;
    let oneIndex = 0;
    return value.replace(/[01258]/g, (character) => {
        if (character === '0') return zeroVariants[zeroIndex++ % zeroVariants.length];
        if (character === '1') return oneVariants[oneIndex++ % oneVariants.length];
        if (character === '2') return 'Z';
        if (character === '5') return 'S';
        return 'B';
    });
}

function renderAlphanumericAmbiguities(value) {
    return value.replace(/O/g, '0').replace(/I/g, '1');
}

function replaceDigitAt(value, index) {
    return value.slice(0, index) + ((Number(value[index]) + 1) % 10) + value.slice(index + 1);
}

test('calculates ICAO Modulus-10 check digits', () => {
    assert.equal(check('L898902C3'), '6');
    assert.equal(check('740812'), '2');
    assert.equal(check('120415'), '9');
    assert.equal(check('ZE184226B<<<<<'), '1');
});

test('validates ICAO reference TD3 and TD1 MRZ examples', () => {
    const td3 = [
        'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<',
        'L898902C36UTO7408122F1204159ZE184226B<<<<<10',
    ];
    const td1 = [
        'I<UTOD231458907<<<<<<<<<<<<<<<',
        '7408122F1204159UTO<<<<<<<<<<<6',
        'ERIKSSON<<ANNA<MARIA<<<<<<<<<<',
    ];
    const referenceDate = new Date(2012, 0, 1);

    assert.equal(parseMrzText(td3.join('\n'), 'passport', 'UTO', referenceDate).ok, true);
    assert.equal(parseMrzText(td1.join('\n'), 'id-card', 'UTO', referenceDate).ok, true);
});

test('reassembles MRZ lines merged or wrapped by OCR', () => {
    const td3 = makeTd3();
    assert.equal(parseMrzText(td3.join(''), 'passport', 'DEU', today).ok, true);
    assert.equal(
        parseMrzText([
            td3[0].slice(0, 20),
            td3[0].slice(20),
            td3[1].slice(0, 25),
            td3[1].slice(25),
        ].join('\n'), 'passport', 'DEU', today).ok,
        true
    );

    const td2 = makeTd2();
    assert.equal(parseMrzText(td2.join(''), 'passport', 'GBR', today).ok, true);

    const td1 = makeTd1();
    assert.equal(parseMrzText(td1.join(''), 'id-card', 'DEU', today).ok, true);
});

test('strips inline whitespace before enforcing each ICAO line length', () => {
    const examples = [
        [makeTd3(), 'passport', 'DEU'],
        [makeTd2(), 'passport', 'GBR'],
        [makeTd1(), 'id-card', 'DEU'],
    ];

    for (const [lines, documentType, country] of examples) {
        const spacedLines = lines.map((line) => (
            `${line.slice(0, 12)} \t ${line.slice(12)}`
        ));
        assert.equal(
            parseMrzText(spacedLines.join('\n'), documentType, country, today).ok,
            true
        );
    }
});

test('restores omitted trailing filler only in unchecked name fields', () => {
    const td3 = makeTd3();
    td3[0] = td3[0].slice(0, -4);
    assert.equal(parseMrzText(td3.join('\n'), 'passport', 'DEU', today).ok, true);

    const td2 = makeTd2();
    td2[0] = td2[0].slice(0, -4);
    assert.equal(parseMrzText(td2.join('\n'), 'passport', 'GBR', today).ok, true);

    const td1 = makeTd1();
    td1[2] = td1[2].slice(0, -4);
    assert.equal(parseMrzText(td1.join('\n'), 'id-card', 'DEU', today).ok, true);
});

test('repairs OCR K, C, L, and S only after confirmed name filler separators', () => {
    const name = 'KCL<<ANNKCL';
    const td3 = makeTd3({ issuer: 'BIH', name });
    const td3FillerStart = 5 + name.length;
    td3[0] = replaceField(td3[0], td3FillerStart + 2, td3FillerStart + 6, () => 'KCLS');
    const repairedTd3 = repairMrzFillerTails(td3, 'TD3');
    assert.equal(repairedTd3[0].slice(5, td3FillerStart), name);
    assert.equal(repairedTd3[0].slice(td3FillerStart, td3FillerStart + 6), '<<<<<<');

    const td2 = makeTd2({ issuer: 'BIH', name });
    const td2FillerStart = 5 + name.length;
    td2[0] = replaceField(td2[0], td2FillerStart + 2, td2FillerStart + 6, () => 'KCLS');
    const repairedTd2 = repairMrzFillerTails(td2, 'TD2');
    assert.equal(repairedTd2[0].slice(5, td2FillerStart), name);
    assert.equal(repairedTd2[0].slice(td2FillerStart, td2FillerStart + 6), '<<<<<<');

    const td1 = makeTd1({ issuer: 'BIH', name });
    td1[2] = replaceField(td1[2], name.length + 2, name.length + 6, () => 'KCLS');
    const repairedTd1 = repairMrzFillerTails(td1, 'TD1');
    assert.equal(repairedTd1[2].slice(0, name.length), name);
    assert.equal(repairedTd1[2].slice(name.length, name.length + 6), '<<<<<<');
});

test('repairs noisy passport prefixes and normalizes trailing filler lengths', () => {
    const td3 = makeTd3({ issuer: 'AZE' });
    td3[0] = `PC${td3[0].slice(2)}`;
    const td3FillerStart = 5 + 'DOE<<JANE'.length;
    td3[0] = replaceField(td3[0], td3FillerStart + 2, td3[0].length, () => (
        `KCLS${'<'.repeat(td3[0].length - td3FillerStart - 6)}`
    ));
    td3[0] += 'KCLS<<<<';
    const td3Result = parseMrzText(td3.join('\n'), 'passport', 'AZE', today);
    assert.equal(td3Result.ok, true, td3Result.error);
    assert.equal(td3[0].length, 52);

    const td2 = makeTd2({ issuer: 'BIH' });
    td2[0] = `PC${td2[0].slice(2)}`;
    const td2FillerStart = 5 + 'DOE<<JANE'.length;
    td2[0] = replaceField(td2[0], td2FillerStart + 2, td2[0].length, () => (
        `KCLS${'<'.repeat(td2[0].length - td2FillerStart - 6)}`
    ));
    td2[0] += 'KCLS<<<<';
    const td2Result = parseMrzText(td2.join('\n'), 'passport', 'BIH', today);
    assert.equal(td2Result.ok, true, td2Result.error);

    const td1 = makeTd1({ issuer: 'BIH' });
    const td1FillerStart = 'DOE<<JANE'.length;
    td1[2] = replaceField(td1[2], td1FillerStart + 2, td1[2].length, () => (
        `KCLS${'<'.repeat(td1[2].length - td1FillerStart - 6)}`
    ));
    td1[2] += 'KCLS<<<<';
    const td1Result = parseMrzText(td1.join('\n'), 'id-card', 'BIH', today);
    assert.equal(td1Result.ok, true, td1Result.error);

    const unknownIssuer = makeTd3({ issuer: 'XXX' });
    unknownIssuer[0] = `PC${unknownIssuer[0].slice(2)}`;
    assert.equal(repairMrzFillerTails(unknownIssuer, 'TD3')[0].startsWith('PCXXX'), true);
});

test('normalizes noisy TD3 and TD2 line-one filler tails before validation', () => {
    const noisyLine = 'P<BIHCEYLA<<<<<KKLKKKLKILKCKLKLKLLLKLLLKLSE1';
    const td3 = makeTd3({ issuer: 'BIH' });
    td3[0] = noisyLine;
    const repairedTd3 = repairMrzFillerTails(td3, 'TD3')[0];
    assert.equal(repairedTd3.length, 44);
    assert.equal(parseMrzText(td3.join('\n'), 'passport', 'BIH', today).ok, true);

    const td2 = makeTd2({ issuer: 'BIH' });
    td2[0] = noisyLine;
    const repairedTd2 = repairMrzFillerTails(td2, 'TD2')[0];
    assert.equal(repairedTd2.length, 36);
    assert.equal(parseMrzText(td2.join('\n'), 'passport', 'BIH', today).ok, true);
});

test('reconstructs TD3 and TD2 line-one prefixes and padding when OCR omits chevrons', () => {
    const td3 = makeTd3({ issuer: 'BIH' });
    td3[0] = 'PBIHCEYLA';
    const td3Result = parseMrzText(td3.join('\n'), 'passport', 'BIH', today);
    assert.equal(td3Result.ok, true, td3Result.error);

    const td2 = makeTd2({ issuer: 'BIH' });
    td2[0] = 'P<BIHCEYLA';
    const td2Result = parseMrzText(td2.join('\n'), 'passport', 'BIH', today);
    assert.equal(td2Result.ok, true, td2Result.error);
});

test('reconstructs TD3 optional-data filler before fixed-position check digits', () => {
    const missingDocumentFillers = makeTd3({
        issuer: 'BIH',
        documentNumber: 'ABC<<<<<<',
    });
    missingDocumentFillers[1] = replaceField(
        missingDocumentFillers[1],
        6,
        8,
        () => ''
    );
    const missingDocumentFillersResult = parseMrzText(
        missingDocumentFillers.join('\n'),
        'passport',
        'BIH',
        today
    );
    assert.equal(missingDocumentFillersResult.ok, true, missingDocumentFillersResult.error);

    const optionalData = `ABCD${'<'.repeat(10)}`;
    const missingFillers = makeTd3({ issuer: 'BIH', optionalData });
    missingFillers[1] = replaceField(missingFillers[1], 36, 40, () => '');
    const missingFillersResult = parseMrzText(
        missingFillers.join('\n'),
        'passport',
        'BIH',
        today
    );
    assert.equal(missingFillersResult.ok, true, missingFillersResult.error);

    const noisyFillers = makeTd3({
        issuer: 'BIH',
        optionalData: `ABCD<${'<'.repeat(9)}`,
    });
    noisyFillers[1] = replaceField(
        noisyFillers[1],
        33,
        42,
        () => 'KCLSI1EKK'
    );
    const noisyFillersResult = parseMrzText(
        noisyFillers.join('\n'),
        'passport',
        'BIH',
        today
    );
    assert.equal(noisyFillersResult.ok, true, noisyFillersResult.error);
});

test('repairs K, C, and L in checked optional-data filler tails', () => {
    const td3 = makeTd3({
        issuer: 'BIH',
        optionalData: `AB12${'<'.repeat(10)}`,
    });
    td3[1] = replaceField(td3[1], 32, 33, () => 'K');
    assert.equal(parseMrzText(td3.join('\n'), 'passport', 'BIH', today).ok, true);

    const td2 = makeTd2({ issuer: 'BIH', optionalData: 'ABC<<<<' });
    td2[1] = replaceField(td2[1], 31, 32, () => 'C');
    assert.equal(parseMrzText(td2.join('\n'), 'passport', 'BIH', today).ok, true);

    const td1 = makeTd1({ issuer: 'BIH' });
    td1[0] = replaceField(td1[0], 15, 16, () => 'L');
    assert.equal(parseMrzText(td1.join('\n'), 'id-card', 'BIH', today).ok, true);
});

test('recovers alphanumeric OCR confusions only when their check digits pass', () => {
    const cases = [
        ['O12345678', '012345678'],
        ['I12345678', '112345678'],
        ['S12345678', '512345678'],
        ['B12345678', '812345678'],
        ['Z12345678', '212345678'],
    ];

    for (const [documentNumber, ocrDocumentNumber] of cases) {
        const lines = makeTd3({ issuer: 'BIH', documentNumber });
        lines[1] = ocrDocumentNumber + lines[1].slice(9);
        const result = parseMrzText(lines.join('\n'), 'passport', 'BIH', today);
        assert.equal(result.ok, true, `${documentNumber} should recover from OCR confusion`);
    }

    const optionalData = 'O1S8Z<<<<<<<<<';
    const ocrOptionalData = optionalData.replace(/[O1S8Z]/g, (character) => ({
        O: '0',
        1: 'I',
        S: '5',
        8: 'B',
        Z: '2',
    })[character]);
    const optionalDataLines = makeTd3({ issuer: 'BIH', optionalData });
    optionalDataLines[1] = replaceField(
        optionalDataLines[1],
        28,
        42,
        () => ocrOptionalData
    );
    const optionalDataResult = parseMrzText(
        optionalDataLines.join('\n'),
        'passport',
        'BIH',
        today
    );
    assert.equal(optionalDataResult.ok, true, optionalDataResult.error);
});

test('normalizes OCR character confusions in TD3 and strips inline whitespace', () => {
    const lines = makeTd3({
        issuer: 'BIH',
        nationality: 'BIH',
        documentNumber: 'O1234567I',
        dateOfBirth: '850815',
        expirationDate: '321028',
        optionalData: 'O123456789I<<<',
        name: 'BOSIS<<JANE',
    });
    lines[0] = replaceField(lines[0], 2, 5, renderLetterAsDigit);
    lines[0] = replaceField(lines[0], 5, lines[0].length, renderLetterAsDigit);
    lines[1] = replaceField(lines[1], 0, 9, renderAlphanumericAmbiguities);
    lines[1] = replaceField(lines[1], 9, 10, renderDigitAsLetter);
    lines[1] = replaceField(lines[1], 10, 13, renderLetterAsDigit);
    lines[1] = replaceField(lines[1], 13, 20, renderDigitAsLetter);
    lines[1] = replaceField(lines[1], 21, 28, renderDigitAsLetter);
    lines[1] = replaceField(lines[1], 28, 42, renderAlphanumericAmbiguities);
    lines[1] = replaceField(lines[1], 42, 44, renderDigitAsLetter);
    lines[0] = `${lines[0].slice(0, 18)} \t ${lines[0].slice(18)}`;
    lines[1] = `${lines[1].slice(0, 22)} ${lines[1].slice(22)}`;

    const result = parseMrzText(lines.join('\n'), 'passport', 'BIH', today);
    assert.equal(result.ok, true, result.error);
    assert.equal(result.issuingState, 'BIH');
    assert.equal(result.dateOfBirth, '1985-08-15');
    assert.equal(result.expirationDate, '2032-10-28');
});

test('corrects ambiguous TD2 optional data only when its composite check digit passes', () => {
    const lines = makeTd2({
        issuer: 'BIH',
        nationality: 'BIH',
        documentNumber: 'O1234567I',
        optionalData: 'O12I<<<',
        name: 'BOSIS<<JANE',
    });
    lines[0] = replaceField(lines[0], 2, 5, renderLetterAsDigit);
    lines[0] = replaceField(lines[0], 5, lines[0].length, renderLetterAsDigit);
    lines[1] = replaceField(lines[1], 0, 9, renderAlphanumericAmbiguities);
    lines[1] = replaceField(lines[1], 9, 10, renderDigitAsLetter);
    lines[1] = replaceField(lines[1], 10, 13, renderLetterAsDigit);
    lines[1] = replaceField(lines[1], 13, 20, renderDigitAsLetter);
    lines[1] = replaceField(lines[1], 21, 28, renderDigitAsLetter);
    lines[1] = replaceField(lines[1], 28, 35, renderAlphanumericAmbiguities);
    lines[1] = replaceField(lines[1], 35, 36, renderDigitAsLetter);

    const result = parseMrzText(lines.join('\n'), 'passport', 'BIH', today);
    assert.equal(result.ok, true, result.error);
});

test('corrects ambiguous TD1 document and optional data using their check digits', () => {
    const lines = makeTd1({
        issuer: 'BIH',
        nationality: 'BIH',
        documentNumber: 'O1234567I',
        dateOfBirth: '850815',
        expirationDate: '321028',
        optionalData: 'O123456789ABCDE',
        secondOptionalData: 'O12I<<<<<<<',
        name: 'BOSIS<<JANE',
    });
    lines[0] = replaceField(lines[0], 2, 5, renderLetterAsDigit);
    lines[0] = replaceField(lines[0], 5, 14, renderAlphanumericAmbiguities);
    lines[0] = replaceField(lines[0], 14, 15, renderDigitAsLetter);
    lines[0] = replaceField(lines[0], 15, 30, renderAlphanumericAmbiguities);
    lines[1] = replaceField(lines[1], 0, 7, renderDigitAsLetter);
    lines[1] = replaceField(lines[1], 8, 15, renderDigitAsLetter);
    lines[1] = replaceField(lines[1], 15, 18, renderLetterAsDigit);
    lines[1] = replaceField(lines[1], 18, 29, renderAlphanumericAmbiguities);
    lines[1] = replaceField(lines[1], 29, 30, renderDigitAsLetter);
    lines[2] = renderLetterAsDigit(lines[2]);

    const result = parseMrzText(lines.join('\n'), 'id-card', 'BIH', today);
    assert.equal(result.ok, true, result.error);
    assert.equal(result.dateOfBirth, '1985-08-15');
    assert.equal(result.expirationDate, '2032-10-28');
});

test('validates TD3 passports and the German issuer alias', () => {
    const lines = makeTd3({ issuer: 'D<<' });
    const result = parseMrzText(lines.join('\n'), 'passport', 'DEU', today);

    assert.deepEqual(result, {
        ok: true,
        format: 'TD3',
        issuingState: 'D<<',
        dateOfBirth: '1990-01-01',
        expirationDate: '2030-12-31',
    });
});

test('validates TD2 passports and the United Kingdom issuer aliases', () => {
    for (const issuer of ['GBR', 'GBD', 'GBN', 'GBO', 'GBP', 'GBS']) {
        const lines = makeTd2({ issuer });
        const result = parseMrzText(lines.join('\n'), 'passport', 'GBR', today);

        assert.equal(result.ok, true, `${issuer} should match the UK selection`);
        assert.equal(result.format, 'TD2');

        const td3 = makeTd3({ issuer });
        const td3Result = parseMrzText(td3.join('\n'), 'passport', 'GBR', today);
        assert.equal(td3Result.ok, true, `${issuer} should match TD3 for the UK selection`);
    }
});

test('validates every selectable issuer for TD1, TD2, and TD3', () => {
    for (const [countryName, issuer] of ICAO_COUNTRIES) {
        const td3 = makeTd3({ issuer, nationality: issuer });
        const td2 = makeTd2({ issuer, nationality: issuer });
        const td1 = makeTd1({ issuer, nationality: issuer });

        assert.equal(
            parseMrzText(td3.join('\n'), 'passport', issuer, today).ok,
            true,
            `${countryName} (${issuer}) should validate as TD3`
        );
        assert.equal(
            parseMrzText(td2.join('\n'), 'passport', issuer, today).ok,
            true,
            `${countryName} (${issuer}) should validate as TD2`
        );
        assert.equal(
            parseMrzText(td1.join('\n'), 'id-card', issuer, today).ok,
            true,
            `${countryName} (${issuer}) should validate as TD1`
        );
    }
});

test('validates TD1 ID cards', () => {
    const lines = makeTd1();
    const result = parseMrzText(lines.join('\n'), 'id-card', 'DEU', today);

    assert.equal(result.ok, true);
    assert.equal(result.format, 'TD1');
});

test('accepts TD1 document codes I, A, and C and extended document numbers', () => {
    for (const documentCode of ['I', 'A', 'C']) {
        const standard = makeTd1({ documentCode });
        assert.equal(
            parseMrzText(standard.join('\n'), 'id-card', 'DEU', today).ok,
            true,
            `${documentCode} document code should parse`
        );
    }

    const extendedNumber = 'A123456789012345';
    const extended = makeTd1({ documentNumber: extendedNumber });
    assert.equal(extended[0][14], '<');
    assert.equal(parseMrzText(extended.join('\n'), 'id-card', 'DEU', today).ok, true);
});

test('rejects invalid TD2 and TD1 check digits', () => {
    for (const index of [9, 19, 27, 35]) {
        const td2 = makeTd2({ optionalData: 'ACD<<<<' });
        td2[1] = replaceDigitAt(td2[1], index);
        assert.equal(
            parseMrzText(td2.join('\n'), 'passport', 'GBR', today).error,
            'invalid-check-digit',
            `expected TD2 check digit at index ${index} to fail`
        );
    }

    for (const [lineIndex, index] of [[0, 14], [1, 6], [1, 14], [1, 29]]) {
        const td1 = makeTd1();
        td1[lineIndex] = replaceDigitAt(td1[lineIndex], index);
        assert.equal(
            parseMrzText(td1.join('\n'), 'id-card', 'DEU', today).error,
            'invalid-check-digit',
            `expected TD1 check digit at line ${lineIndex}, index ${index} to fail`
        );
    }
});

test('rejects invalid TD3 document, DOB, expiry, optional-data, and composite digits', () => {
    const line2CheckIndexes = [9, 19, 27, 42, 43];
    for (const index of line2CheckIndexes) {
        const lines = makeTd3();
        lines[1] = replaceDigitAt(lines[1], index);
        assert.equal(
            parseMrzText(lines.join('\n'), 'passport', 'DEU', today).error,
            'invalid-check-digit',
            `expected check digit at index ${index} to fail`
        );
    }
});

test('rejects incorrect country, layout, and expired documents', () => {
    const wrongCountry = makeTd3({ issuer: 'USA' });
    assert.equal(
        parseMrzText(wrongCountry.join('\n'), 'passport', 'DEU', today).error,
        'country-mismatch'
    );

    const idCard = makeTd1();
    assert.equal(
        parseMrzText(idCard.join('\n'), 'passport', 'DEU', today).error,
        'mrz-not-found'
    );

    const expired = makeTd3({ expirationDate: '700101' });
    assert.equal(
        parseMrzText(expired.join('\n'), 'passport', 'DEU', today).error,
        'expired'
    );
});

test('rejects invalid dates and incorrect line lengths', () => {
    const invalidDate = makeTd3({ dateOfBirth: '900231' });
    assert.equal(
        parseMrzText(invalidDate.join('\n'), 'passport', 'DEU', today).error,
        'invalid-date'
    );

    const truncated = makeTd3();
    truncated[1] = truncated[1].slice(0, -1);
    assert.equal(
        parseMrzText(truncated.join('\n'), 'passport', 'DEU', today).error,
        'invalid-check-digit'
    );
});

test('rejects a document code that conflicts with the selected MRZ layout', () => {
    const td3 = makeTd3();
    td3[0] = `I${td3[0].slice(1)}`;
    assert.equal(
        parseMrzText(td3.join('\n'), 'passport', 'DEU', today).error,
        'invalid-document-type'
    );

    const td1 = makeTd1();
    td1[1] = `${td1[1].slice(0, 7)}Z${td1[1].slice(8)}`;
    assert.equal(
        parseMrzText(td1.join('\n'), 'id-card', 'DEU', today).error,
        'invalid-document-type'
    );

    const misreadTd1Code = makeTd1();
    misreadTd1Code[0] = `1${misreadTd1Code[0].slice(1)}`;
    assert.equal(
        parseMrzText(misreadTd1Code.join('\n'), 'id-card', 'DEU', today).ok,
        true
    );
});
