import test from 'node:test';
import assert from 'node:assert/strict';
import { getCameraGuideCrop, getMrzCropRegion } from '../public/camera-crop.js';

test('maps the centered guide to video coordinates when video fills the viewfinder', () => {
    const crop = getCameraGuideCrop(
        { left: 0, top: 0, width: 400, height: 700 },
        { left: 24, top: 220, right: 376, bottom: 468, width: 352, height: 248 },
        1080,
        1890
    );

    assert.deepEqual(crop, {
        left: 0.06,
        top: 220 / 700,
        width: 0.88,
        height: 248 / 700,
    });
});

test('accounts for letterboxing when mapping the viewfinder guide', () => {
    const crop = getCameraGuideCrop(
        { left: 100, top: 200, width: 400, height: 700 },
        { left: 120, top: 450, right: 480, bottom: 650, width: 360, height: 200 },
        1920,
        1080
    );

    assert.deepEqual(crop, {
        left: 0.05,
        top: 12.5 / 225,
        width: 0.9,
        height: 200 / 225,
    });
});

test('returns no crop when most of the guide is outside the visible video', () => {
    const crop = getCameraGuideCrop(
        { left: 0, top: 0, width: 400, height: 700 },
        { left: 24, top: 100, right: 376, bottom: 400, width: 352, height: 300 },
        1920,
        1080
    );

    assert.equal(crop, null);
});

test('selects a lower MRZ band based on the document mode', () => {
    const viewfinderCrop = { left: 0.1, top: 0.2, width: 0.8, height: 0.6 };
    const passportCrop = getMrzCropRegion(viewfinderCrop, 'passport');

    assert.equal(passportCrop.left, 0.1);
    assert.ok(Math.abs(passportCrop.top - 0.632) < 1e-12);
    assert.equal(passportCrop.width, 0.8);
    assert.ok(Math.abs(passportCrop.height - 0.168) < 1e-12);

    const idCardCrop = getMrzCropRegion(viewfinderCrop, 'id-card');
    assert.equal(idCardCrop.left, 0.1);
    assert.ok(Math.abs(idCardCrop.top - 0.59) < 1e-12);
    assert.equal(idCardCrop.width, 0.8);
    assert.ok(Math.abs(idCardCrop.height - 0.21) < 1e-12);

    assert.equal(getMrzCropRegion(viewfinderCrop, 'other'), null);
});

test('clamps the MRZ crop to video bounds without adding horizontal margin', () => {
    const crop = getMrzCropRegion(
        { left: -0.02, top: 0.1, width: 1.04, height: 0.8 },
        'passport'
    );

    assert.equal(crop.left, 0);
    assert.equal(crop.width, 1);
    assert.ok(Math.abs(crop.top - 0.676) < 1e-12);
    assert.ok(Math.abs(crop.height - 0.224) < 1e-12);
});
