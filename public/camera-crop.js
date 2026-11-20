const MRZ_BAND_TOP = {
    passport: 0.72,
    'id-card': 0.65,
};

export function getCameraGuideCrop(videoRect, guideRect, videoWidth, videoHeight) {
    if (
        !videoRect ||
        !guideRect ||
        !Number.isFinite(videoWidth) ||
        !Number.isFinite(videoHeight) ||
        videoWidth <= 0 ||
        videoHeight <= 0 ||
        videoRect.width <= 0 ||
        videoRect.height <= 0 ||
        guideRect.width <= 0 ||
        guideRect.height <= 0
    ) {
        return null;
    }

    const scale = Math.min(videoRect.width / videoWidth, videoRect.height / videoHeight);
    const contentWidth = videoWidth * scale;
    const contentHeight = videoHeight * scale;
    const contentLeft = videoRect.left + (videoRect.width - contentWidth) / 2;
    const contentTop = videoRect.top + (videoRect.height - contentHeight) / 2;
    const left = Math.max(guideRect.left, contentLeft);
    const top = Math.max(guideRect.top, contentTop);
    const right = Math.min(guideRect.right, contentLeft + contentWidth);
    const bottom = Math.min(guideRect.bottom, contentTop + contentHeight);
    const visibleArea = Math.max(0, right - left) * Math.max(0, bottom - top);
    const guideArea = guideRect.width * guideRect.height;

    if (visibleArea / guideArea < 0.9) return null;

    return {
        left: (left - contentLeft) / contentWidth,
        top: (top - contentTop) / contentHeight,
        width: (right - left) / contentWidth,
        height: (bottom - top) / contentHeight,
    };
}

export function getMrzCropRegion(viewfinderCrop, documentType) {
    const bandTop = MRZ_BAND_TOP[documentType];
    if (!viewfinderCrop || bandTop === undefined) return null;
    const left = Math.max(0, Math.min(1, viewfinderCrop.left));
    const right = Math.max(
        left,
        Math.min(1, viewfinderCrop.left + viewfinderCrop.width)
    );
    const top = Math.max(
        0,
        Math.min(1, viewfinderCrop.top + viewfinderCrop.height * bandTop)
    );
    const bottom = Math.max(
        top,
        Math.min(1, viewfinderCrop.top + viewfinderCrop.height)
    );

    return {
        left,
        top,
        width: right - left,
        height: bottom - top,
    };
}
