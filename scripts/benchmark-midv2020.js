import { readdir, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createWorker } from 'tesseract.js';
import { ICAO_COUNTRIES } from '../public/icao-countries.js';
import { parseMrzText } from '../public/mrz.js';

const ROOT_DIR = fileURLToPath(new URL('../', import.meta.url));
const IMAGE_EXTENSIONS = new Set([
    '.bmp',
    '.jpeg',
    '.jpg',
    '.png',
    '.tif',
    '.tiff',
    '.webp',
]);
const AMBIGUOUS_DIGITS = {
    O: 'O/0',
    D: 'O/0',
    Q: 'O/0',
    I: 'I/1',
    L: 'I/1',
    S: 'S/5',
    B: 'B/8',
    Z: 'Z/2',
};
const AMBIGUOUS_LETTERS = {
    '0': '0/O',
    '1': '1/I',
    '5': '5/S',
    '8': '8/B',
    '2': '2/Z',
};

async function findImages(directory) {
    const images = [];
    for (const entry of await readdir(directory, { withFileTypes: true })) {
        const path = resolve(directory, entry.name);
        if (entry.isDirectory()) {
            images.push(...await findImages(path));
        } else if (entry.isFile() && IMAGE_EXTENSIONS.has(
            entry.name.slice(entry.name.lastIndexOf('.')).toLowerCase()
        )) {
            images.push(path);
        }
    }
    return images;
}

function getLikelyConfusions(text, counts) {
    const lines = text.toUpperCase().split(/\r?\n/).map((line) => (
        line.replace(/[^A-Z0-9<]/g, '')
    ));
    for (const line of lines) {
        if (line.length === 44) {
            if (line[0] === 'P') {
                countAmbiguities(line, [[0, 5]], AMBIGUOUS_LETTERS, counts);
            } else {
                countAmbiguities(line, [[9, 10], [13, 20], [21, 28], [42, 44]], AMBIGUOUS_DIGITS, counts);
            }
        } else if (line.length === 36) {
            if (line[0] === 'P') {
                countAmbiguities(line, [[0, 5]], AMBIGUOUS_LETTERS, counts);
            } else {
                countAmbiguities(line, [[9, 10], [13, 20], [21, 28], [35, 36]], AMBIGUOUS_DIGITS, counts);
            }
        } else if (line.length === 30) {
            if (['I', 'A', 'C'].includes(line[0])) {
                countAmbiguities(line, [[0, 5]], AMBIGUOUS_LETTERS, counts);
                countAmbiguities(line, [[14, 15]], AMBIGUOUS_DIGITS, counts);
            } else if (/^\d/.test(line)) {
                countAmbiguities(line, [[0, 7], [8, 15], [29, 30]], AMBIGUOUS_DIGITS, counts);
            }
        }
    }
}

function countAmbiguities(line, ranges, mapping, counts) {
    for (const [start, end] of ranges) {
        for (const character of line.slice(start, end)) {
            const confusion = mapping[character];
            if (confusion) counts[confusion] = (counts[confusion] || 0) + 1;
        }
    }
}

function analyzeMrz(text, date) {
    let sawMrz = false;
    let checkDigitsPassed = false;
    const countryCodes = ICAO_COUNTRIES.map(([, code]) => code);

    for (const documentType of ['passport', 'id-card']) {
        for (const countryCode of countryCodes) {
            const result = parseMrzText(text, documentType, countryCode, date);
            if (result.ok) {
                return { parsed: true, sawMrz: true, checkDigitsPassed: true };
            }
            if (result.error !== 'mrz-not-found' && result.error !== 'invalid-selection') {
                sawMrz = true;
            }
            if (result.error === 'expired' || result.error === 'invalid-date') {
                checkDigitsPassed = true;
            }
        }
    }
    return { parsed: false, sawMrz, checkDigitsPassed };
}

async function main() {
    const inputDirectory = process.argv[2] || process.env.MIDV2020_DIR;
    if (!inputDirectory) {
        throw new Error('Provide an extracted image directory: node scripts/benchmark-midv2020.js <directory>');
    }
    const directory = resolve(inputDirectory);
    if (!(await stat(directory)).isDirectory()) {
        throw new Error('The MIDV-2020 input path must be a directory');
    }
    const images = (await findImages(directory)).sort();
    if (!images.length) throw new Error('No supported images were found in the input directory');

    const workerOptions = {
        logger: () => {},
    };
    if (existsSync(resolve(ROOT_DIR, 'eng.traineddata'))) {
        workerOptions.langPath = ROOT_DIR;
    }
    const worker = await createWorker('eng', 1, workerOptions);
    const confusionCounts = {};
    let parseCount = 0;
    let mrzCount = 0;
    let checkDigitsPassedCount = 0;
    let totalLatencyMs = 0;
    const benchmarkDate = new Date();

    try {
        for (const [index, image] of images.entries()) {
            const startedAt = performance.now();
            const recognition = await worker.recognize(image);
            let text = recognition.data.text;
            const analysis = analyzeMrz(text, benchmarkDate);
            getLikelyConfusions(text, confusionCounts);
            text = '';
            recognition.data.text = '';

            const latencyMs = performance.now() - startedAt;
            totalLatencyMs += latencyMs;
            if (analysis.parsed) parseCount++;
            if (analysis.sawMrz) mrzCount++;
            if (analysis.checkDigitsPassed) checkDigitsPassedCount++;
            process.stdout.write(
                `image ${String(index + 1).padStart(4, '0')}: `
                + `parsed=${analysis.parsed} mrz=${analysis.sawMrz} `
                + `latency=${latencyMs.toFixed(1)}ms\n`
            );
        }
    } finally {
        await worker.terminate();
    }

    process.stdout.write('\nMIDV-2020 benchmark summary (no OCR text or filenames emitted)\n');
    process.stdout.write(`Images: ${images.length}\n`);
    process.stdout.write(`MRZ detection rate: ${(mrzCount / images.length * 100).toFixed(1)}% (${mrzCount}/${images.length})\n`);
    process.stdout.write(`Document/MRZ parse rate: ${(parseCount / images.length * 100).toFixed(1)}% (${parseCount}/${images.length})\n`);
    process.stdout.write(
        `Check-digit pass rate: ${mrzCount ? (checkDigitsPassedCount / mrzCount * 100).toFixed(1) : '0.0'}% `
        + `(${checkDigitsPassedCount}/${mrzCount} MRZ detections)\n`
    );
    process.stdout.write(`Average latency: ${(totalLatencyMs / images.length).toFixed(1)}ms\n`);
    process.stdout.write(`Total latency: ${totalLatencyMs.toFixed(1)}ms\n`);
    process.stdout.write(`Likely OCR character confusions in MRZ fields: ${JSON.stringify(confusionCounts)}\n`);
}

main().catch((error) => {
    console.error(error instanceof Error ? error.message : 'MIDV-2020 benchmark failed');
    process.exitCode = 1;
});
