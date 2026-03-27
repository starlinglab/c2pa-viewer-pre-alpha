/**
 * JPEG/APP1/APP11 parser for the early CAI pre-alpha format.
 * Everything surfaced by this parser is derived from bytes in the JPEG.
 */

class JUMBFParser {
    constructor() {
        this.textDecoder = new TextDecoder('utf-8', { fatal: false });
        this.attributeOidMap = {
            '2.5.4.3': 'CN',
            '2.5.4.4': 'SN',
            '2.5.4.5': 'serialNumber',
            '2.5.4.6': 'C',
            '2.5.4.7': 'L',
            '2.5.4.8': 'ST',
            '2.5.4.9': 'street',
            '2.5.4.10': 'O',
            '2.5.4.11': 'OU',
            '2.5.4.12': 'title',
            '2.5.4.42': 'GN',
            '1.2.840.113549.1.9.1': 'emailAddress'
        };
        this.algorithmOidMap = {
            '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
            '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
            '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
            '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
            '1.2.840.10045.4.3.2': 'ecdsaWithSHA256',
            '1.2.840.10045.4.3.3': 'ecdsaWithSHA384',
            '1.2.840.10045.4.3.4': 'ecdsaWithSHA512'
        };
    }

    async parseImage(arrayBuffer) {
        const bytes = new Uint8Array(arrayBuffer);
        const result = {
            fileInfo: this.getFileInfo(arrayBuffer),
            jpegSegments: [],
            jumbfBoxes: [],
            xmpData: null,
            exifData: null,
            caiClaims: {},
            assertions: [],
            errors: [],
            certificates: [],
            contentRecord: this.createEmptyContentRecord(),
            structuredMetadata: {},
            detailedAssertions: {
                rights: null,
                identity: null,
                actions: null,
                acquisition: null,
                integrity: null
            }
        };

        if (!result.fileInfo.isJPEG) {
            result.errors.push('File is not a JPEG image.');
            return result;
        }

        try {
            this.parseJPEGSegments(bytes, result);
            result.certificates = this.extractCertificates(bytes);
            this.processCAIData(result);
            if (result.caiClaims.publicKey) {
                result.caiClaims.publicKeyInfo = await this.parsePGPPublicKey(result.caiClaims.publicKey);
            }
        } catch (error) {
            result.errors.push(`Parse error: ${error.message}`);
        }

        return result;
    }

    createEmptyContentRecord() {
        return {
            producer: null,
            producedWith: null,
            editsAndActivity: [],
            contentElements: [],
            providers: [],
            identifiedBy: null,
            signedBy: null
        };
    }

    getFileInfo(arrayBuffer) {
        const bytes = new Uint8Array(arrayBuffer);
        return {
            size: arrayBuffer.byteLength,
            isJPEG: bytes[0] === 0xFF && bytes[1] === 0xD8,
            parsedAt: new Date().toISOString()
        };
    }

    parseJPEGSegments(bytes, result) {
        let offset = 2;

        while (offset < bytes.length - 1) {
            if (bytes[offset] !== 0xFF) {
                offset += 1;
                continue;
            }

            while (offset < bytes.length && bytes[offset] === 0xFF) {
                offset += 1;
            }
            if (offset >= bytes.length) {
                break;
            }

            const marker = bytes[offset];
            offset += 1;

            if (marker === 0xD9 || marker === 0xDA) {
                break;
            }

            if (this.isStandaloneMarker(marker)) {
                continue;
            }

            if (offset + 1 >= bytes.length) {
                break;
            }

            const segmentLength = (bytes[offset] << 8) | bytes[offset + 1];
            if (segmentLength < 2 || offset + segmentLength > bytes.length) {
                result.errors.push(`Invalid JPEG segment length near byte ${offset - 1}.`);
                break;
            }

            const dataStart = offset + 2;
            const dataEnd = offset + segmentLength;
            const segmentData = bytes.slice(dataStart, dataEnd);
            const markerOffset = offset - 1;

            result.jpegSegments.push({
                marker,
                offset: markerOffset,
                length: segmentLength
            });

            if (marker === 0xE1) {
                this.parseAPP1Segment(segmentData, result);
            } else if (marker === 0xEB) {
                this.parseAPP11Segment(segmentData, markerOffset, result);
            }

            offset = dataEnd;
        }
    }

    isStandaloneMarker(marker) {
        return (marker >= 0xD0 && marker <= 0xD7) || marker === 0x01;
    }

    parseAPP1Segment(data, result) {
        try {
            if (this.isXMPData(data)) {
                const xmpString = this.extractXMPString(data);
                result.xmpData = {
                    raw: xmpString,
                    size: data.length
                };
                this.extractCAIFromXMP(xmpString, result);
            } else if (this.isEXIFData(data)) {
                result.exifData = this.parseEXIFData(data);
                this.mergeEXIFIntoContentRecord(result.exifData, result);
            }
        } catch (error) {
            result.errors.push(`APP1 parse error: ${error.message}`);
        }
    }

    parseAPP11Segment(data, segmentOffset, result) {
        try {
            const segmentText = this.sanitizeText(this.textDecoder.decode(data));
            const boxes = this.extractBoxesFromSegment(data, segmentText, segmentOffset);
            result.jumbfBoxes.push(...boxes);
            this.extractStandaloneMetadataFromSegment(segmentText, result);
        } catch (error) {
            result.errors.push(`APP11 parse error: ${error.message}`);
        }
    }

    extractStandaloneMetadataFromSegment(segmentText, result) {
        const publicKeyMarker = segmentText.indexOf('"starling:PublicKey"');
        if (publicKeyMarker >= 0) {
            const jsonStart = segmentText.lastIndexOf('{', publicKeyMarker);
            if (jsonStart >= 0) {
                const extracted = this.extractBalancedJson(segmentText, jsonStart);
                if (extracted) {
                    try {
                        const parsed = JSON.parse(extracted.json);
                        if (parsed['starling:PublicKey']) {
                            result.caiClaims.publicKey = parsed['starling:PublicKey'];
                            result.structuredMetadata['starling:PublicKey'] = parsed['starling:PublicKey'];
                        }
                    } catch {
                        // Ignore standalone JSON parsing failures.
                    }
                }
            }
        }
    }

    isXMPData(data) {
        const probe = this.textDecoder.decode(data.slice(0, 64));
        return probe.includes('http://ns.adobe.com/xap/1.0/') || probe.includes('<?xpacket');
    }

    isEXIFData(data) {
        return data.length >= 6 &&
            data[0] === 0x45 && data[1] === 0x78 &&
            data[2] === 0x69 && data[3] === 0x66 &&
            data[4] === 0x00 && data[5] === 0x00;
    }

    extractXMPString(data) {
        const text = this.textDecoder.decode(data);
        const start = text.indexOf('<?xpacket');
        const end = text.lastIndexOf('<?xpacket end=');

        if (start >= 0 && end >= start) {
            const closing = text.indexOf('?>', end);
            return text.slice(start, closing >= 0 ? closing + 2 : text.length);
        }

        return text;
    }

    extractCAIFromXMP(xmpString, result) {
        const values = {};

        if (typeof DOMParser !== 'undefined') {
            try {
                const xml = new DOMParser().parseFromString(xmpString, 'application/xml');
                if (!xml.querySelector('parsererror')) {
                    const descriptions = Array.from(xml.getElementsByTagNameNS('*', 'Description'));
                    descriptions.forEach((description) => {
                        for (const attribute of Array.from(description.attributes)) {
                            const key = attribute.localName || attribute.name;
                            if (attribute.value && attribute.value.trim()) {
                                values[key] = attribute.value.trim();
                            }
                        }
                    });
                }
            } catch (error) {
                result.errors.push(`XMP XML parse error: ${error.message}`);
            }
        }

        if (Object.keys(values).length === 0) {
            const attributePattern = /([A-Za-z_][\w.-]*):([A-Za-z_][\w.-]*)="([^"]+)"/g;
            let match;
            while ((match = attributePattern.exec(xmpString)) !== null) {
                values[match[2]] = match[3];
            }
        }

        result.structuredMetadata = {
            ...result.structuredMetadata,
            ...values
        };

        if (values.provenance) {
            result.caiClaims.provenance = values.provenance;
        }
        if (values.title) {
            result.caiClaims.title = values.title;
        }
        if (values.format) {
            result.caiClaims.format = values.format;
        }
    }

    parseEXIFData(data) {
        const exif = {
            found: true,
            size: data.length,
            tags: {}
        };

        try {
            const tiffOffset = 6;
            if (data.length < tiffOffset + 8) {
                return exif;
            }

            const littleEndian = data[tiffOffset] === 0x49 && data[tiffOffset + 1] === 0x49;
            const bigEndian = data[tiffOffset] === 0x4D && data[tiffOffset + 1] === 0x4D;
            if (!littleEndian && !bigEndian) {
                return exif;
            }

            const byteOrder = littleEndian ? 'LE' : 'BE';
            const firstIFDOffset = this.readUInt32(data, tiffOffset + 4, byteOrder);
            this.parseEXIFIFD(data, tiffOffset, tiffOffset + firstIFDOffset, byteOrder, exif.tags, 0, 'ifd0');
            this.finalizeEXIFTags(exif.tags);
        } catch (error) {
            exif.error = error.message;
        }

        return exif;
    }

    parseEXIFIFD(data, tiffOffset, ifdOffset, byteOrder, tags, depth, directoryType) {
        if (depth > 4 || ifdOffset <= 0 || ifdOffset + 2 > data.length) {
            return;
        }

        const entryCount = this.readUInt16(data, ifdOffset, byteOrder);
        for (let i = 0; i < entryCount; i += 1) {
            const entryOffset = ifdOffset + 2 + (i * 12);
            if (entryOffset + 12 > data.length) {
                break;
            }

            const tag = this.readUInt16(data, entryOffset, byteOrder);
            const type = this.readUInt16(data, entryOffset + 2, byteOrder);
            const count = this.readUInt32(data, entryOffset + 4, byteOrder);
            const valueOffset = entryOffset + 8;
            const value = this.readEXIFValue(data, tiffOffset, type, count, valueOffset, byteOrder);

            const tagName = this.getEXIFTagName(tag, directoryType);
            if (tagName && value !== null && value !== '') {
                tags[tagName] = value;
            }

            if (tag === 0x8769 || tag === 0x8825) {
                const nestedOffset = this.readUInt32(data, valueOffset, byteOrder);
                if (nestedOffset > 0) {
                    this.parseEXIFIFD(
                        data,
                        tiffOffset,
                        tiffOffset + nestedOffset,
                        byteOrder,
                        tags,
                        depth + 1,
                        tag === 0x8825 ? 'gps' : 'exif'
                    );
                }
            }
        }
    }

    readEXIFValue(data, tiffOffset, type, count, valueOffset, byteOrder) {
        const typeSizes = {
            1: 1,
            2: 1,
            3: 2,
            4: 4,
            5: 8,
            7: 1,
            9: 4,
            10: 8
        };

        const size = typeSizes[type];
        if (!size) {
            return null;
        }

        const totalSize = size * count;
        let dataOffset = valueOffset;
        if (totalSize > 4) {
            const pointedOffset = this.readUInt32(data, valueOffset, byteOrder);
            dataOffset = tiffOffset + pointedOffset;
        }

        if (dataOffset < 0 || dataOffset + totalSize > data.length) {
            return null;
        }

        switch (type) {
            case 2:
            case 7:
                return this.textDecoder.decode(data.slice(dataOffset, dataOffset + totalSize)).replace(/\0+$/, '').trim();
            case 3:
                return count === 1 ? this.readUInt16(data, dataOffset, byteOrder) : this.readUIntArray(data, dataOffset, count, 2, byteOrder);
            case 4:
                return count === 1 ? this.readUInt32(data, dataOffset, byteOrder) : this.readUIntArray(data, dataOffset, count, 4, byteOrder);
            case 5:
                return count === 1
                    ? this.readRational(data, dataOffset, byteOrder, false)
                    : this.readRationalArray(data, dataOffset, count, byteOrder, false);
            case 10:
                return count === 1
                    ? this.readRational(data, dataOffset, byteOrder, true)
                    : this.readRationalArray(data, dataOffset, count, byteOrder, true);
            default:
                return null;
        }
    }

    finalizeEXIFTags(tags) {
        const lat = this.normalizeGPSCoordinate(tags.GPSLatitude, tags.GPSLatitudeRef);
        const lng = this.normalizeGPSCoordinate(tags.GPSLongitude, tags.GPSLongitudeRef);

        if (lat !== null) {
            tags.GPSLatitudeDecimal = lat;
        }
        if (lng !== null) {
            tags.GPSLongitudeDecimal = lng;
        }
        if (lat !== null && lng !== null) {
            tags.Location = `${lat.toFixed(6)}, ${lng.toFixed(6)}`;
        }
    }

    normalizeGPSCoordinate(value, ref) {
        if (!Array.isArray(value) || value.length < 3) {
            return null;
        }

        const [degrees, minutes, seconds] = value.map((part) => Number(part) || 0);
        let decimal = degrees + (minutes / 60) + (seconds / 3600);
        if (ref === 'S' || ref === 'W') {
            decimal *= -1;
        }
        return Number.isFinite(decimal) ? decimal : null;
    }

    mergeEXIFIntoContentRecord(exifData, result) {
        if (!exifData || !exifData.tags) {
            return;
        }

        result.structuredMetadata = {
            ...result.structuredMetadata,
            ...exifData.tags
        };

        if (!result.contentRecord.producedWith && exifData.tags.Software) {
            result.contentRecord.producedWith = exifData.tags.Software;
        }
    }

    getEXIFTagName(tag, directoryType) {
        const commonTagMap = {
            0x010E: 'ImageDescription',
            0x010F: 'Make',
            0x0110: 'Model',
            0x0131: 'Software',
            0x0132: 'ModifyDate',
            0x8298: 'Copyright',
            0x9003: 'DateTimeOriginal',
            0x9004: 'CreateDate'
        };

        const gpsTagMap = {
            0x0001: 'GPSLatitudeRef',
            0x0002: 'GPSLatitude',
            0x0003: 'GPSLongitudeRef',
            0x0004: 'GPSLongitude',
            0x0005: 'GPSAltitudeRef',
            0x0006: 'GPSAltitude',
            0x0007: 'GPSTimeStamp',
            0x0012: 'GPSMapDatum',
            0x001D: 'GPSDateStamp'
        };

        if (directoryType === 'gps') {
            return gpsTagMap[tag] || null;
        }

        return commonTagMap[tag] || null;
    }

    extractBoxesFromSegment(segmentBytes, segmentText, segmentOffset) {
        const labels = [];
        const labelPattern = /\b(cai\.[A-Za-z0-9._-]+|adobe\.asset\.info|starling\.[A-Za-z0-9._-]+)\b/g;
        let match;

        while ((match = labelPattern.exec(segmentText)) !== null) {
            labels.push({
                label: match[1],
                textIndex: match.index
            });
        }

        const boxes = [];
        let index = 0;

        while (index < labels.length) {
            const entry = labels[index];
            const remainingText = segmentText.slice(entry.textIndex);
            const payload = this.extractJsonPayloadFromText(remainingText, entry.label);
            const fallbackEnd = index + 1 < labels.length ? labels[index + 1].textIndex : segmentText.length;
            const payloadEnd = payload ? entry.textIndex + payload.end : fallbackEnd;
            const boxEnd = Math.max(entry.textIndex + entry.label.length, Math.min(segmentText.length, payloadEnd));
            const boxText = segmentText.slice(entry.textIndex, boxEnd);

            boxes.push({
                offset: segmentOffset + entry.textIndex,
                size: Math.max(1, boxEnd - entry.textIndex),
                labels: [entry.label],
                type: 'CAI',
                jsonData: payload ? [payload.value] : null,
                assertionData: payload ? payload.value : null,
                content: boxText.trim().slice(0, 500)
            });

            index += 1;
            while (index < labels.length && labels[index].textIndex < boxEnd) {
                index += 1;
            }
        }

        if (boxes.length === 0 && segmentText.includes('JUMB')) {
            boxes.push({
                offset: segmentOffset,
                size: segmentBytes.length,
                labels: [],
                type: 'JUMBF',
                jsonData: null,
                assertionData: null,
                content: segmentText.trim().slice(0, 500)
            });
        }

        return boxes;
    }

    extractJsonPayloadFromText(text, label) {
        const bodyWindow = text.slice(label.length, label.length + 96);
        const jsonMarker = bodyWindow.indexOf('json');
        if (jsonMarker < 0) {
            return null;
        }

        const leadingText = bodyWindow.slice(0, jsonMarker);
        if (/\b(cai\.[A-Za-z0-9._-]+|adobe\.asset\.info|starling\.[A-Za-z0-9._-]+)\b/.test(leadingText)) {
            return null;
        }

        const payloadStart = this.findFirstJsonChar(text, label.length + jsonMarker + 4);
        if (payloadStart < 0) {
            return null;
        }

        const extracted = this.extractBalancedJson(text, payloadStart);
        if (!extracted) {
            return null;
        }

        try {
            return {
                raw: extracted.json,
                value: JSON.parse(extracted.json),
                end: extracted.end
            };
        } catch (error) {
            return null;
        }
    }

    findFirstJsonChar(text, start) {
        for (let i = start; i < text.length; i += 1) {
            if (text[i] === '{' || text[i] === '[') {
                return i;
            }
        }
        return -1;
    }

    extractBalancedJson(text, start) {
        const opening = text[start];
        const closing = opening === '{' ? '}' : ']';
        let depth = 0;
        let inString = false;
        let escaped = false;

        for (let i = start; i < text.length; i += 1) {
            const char = text[i];

            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (char === '\\') {
                    escaped = true;
                } else if (char === '"') {
                    inString = false;
                }
                continue;
            }

            if (char === '"') {
                inString = true;
                continue;
            }

            if (char === opening) {
                depth += 1;
            } else if (char === closing) {
                depth -= 1;
                if (depth === 0) {
                    return {
                        json: text.slice(start, i + 1),
                        end: i + 1
                    };
                }
            }
        }

        return null;
    }

    processCAIData(result) {
        const providers = new Set(result.contentRecord.providers);
        const assertionsByType = new Map();
        const actionEntries = [];

        result.jumbfBoxes.forEach((box) => {
            const label = this.normalizeAssertionLabel(box.labels[0], box.assertionData);
            const payload = box.assertionData;
            if (!label) {
                return;
            }

            if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
                if (payload['starling:PublicKey']) {
                    result.caiClaims.publicKey = payload['starling:PublicKey'];
                }
            }

            assertionsByType.set(label, {
                type: label,
                source: 'JUMBF',
                content: box.content,
                jsonData: box.jsonData,
                assertionData: payload
            });

            switch (label) {
                case 'cai.claim':
                    this.applyClaimPayload(payload, result);
                    providers.add('CAI');
                    break;
                case 'cai.assertions':
                    providers.add('CAI');
                    break;
                case 'cai.rights':
                    if (payload && typeof payload === 'object') {
                        result.detailedAssertions.rights = payload;
                        result.structuredMetadata = { ...result.structuredMetadata, ...payload };
                        if (!result.contentRecord.producer && payload.copyright) {
                            result.contentRecord.producer = payload.copyright;
                        }
                    }
                    providers.add('CAI');
                    break;
                case 'cai.identity':
                    if (payload && typeof payload === 'object') {
                        result.detailedAssertions.identity = payload;
                        result.structuredMetadata = { ...result.structuredMetadata, ...payload };
                        if (!result.contentRecord.producer) {
                            result.contentRecord.producer = payload.display || payload.producer || payload.creator || null;
                        }
                    }
                    providers.add('CAI');
                    break;
                case 'cai.actions':
                    if (Array.isArray(payload)) {
                        result.detailedAssertions.actions = payload;
                        actionEntries.push(...payload);
                    }
                    providers.add('CAI');
                    break;
                case 'cai.acquisition_1':
                    if (payload && typeof payload === 'object') {
                        result.detailedAssertions.acquisition = payload;
                        result.structuredMetadata = { ...result.structuredMetadata, ...payload };
                    }
                    providers.add('CAI');
                    break;
                case 'adobe.asset.info':
                    if (payload && typeof payload === 'object') {
                        result.caiClaims.assetInfo = payload;
                        result.structuredMetadata = { ...result.structuredMetadata, ...payload };
                    }
                    providers.add('Adobe');
                    break;
                case 'starling.integrity':
                    if (payload && typeof payload === 'object') {
                        result.detailedAssertions.integrity = payload;
                        result.caiClaims.starlingIntegrity = payload;
                        result.structuredMetadata = { ...result.structuredMetadata, ...payload };
                        if (payload['starling:PublicKey']) {
                            result.caiClaims.publicKey = payload['starling:PublicKey'];
                        }
                    }
                    providers.add('Starling');
                    break;
                case 'cai.signature':
                    {
                        const placeholderMatch = box.content && box.content.match(/signature placeholder:([^\s]+)/i);
                        if (placeholderMatch) {
                            result.caiClaims.signaturePlaceholder = placeholderMatch[1];
                        }
                        providers.add('CAI');
                    }
                    break;
                default:
                    if (label.startsWith('cai.')) {
                        providers.add('CAI');
                    }
                    if (label.startsWith('adobe.')) {
                        providers.add('Adobe');
                    }
                    if (label.startsWith('starling.')) {
                        providers.add('Starling');
                    }
                    break;
            }
        });

        result.assertions = Array.from(assertionsByType.values());
        result.contentRecord.providers = Array.from(providers);

        if (actionEntries.length > 0) {
            result.contentRecord.editsAndActivity = actionEntries.map((entry) => this.formatActionEntry(entry));
            const latestAction = actionEntries[actionEntries.length - 1];
            if (!result.contentRecord.producedWith && latestAction['stEvt:softwareAgent']) {
                result.contentRecord.producedWith = latestAction['stEvt:softwareAgent'];
            }
            if (latestAction['stEvt:when']) {
                result.caiClaims.when = latestAction['stEvt:when'];
            }
            result.caiClaims.actions = actionEntries;
        }

        if (!result.contentRecord.producedWith && result.caiClaims.recorder) {
            result.contentRecord.producedWith = result.caiClaims.recorder;
        }

        if (result.caiClaims.recorder && /starling store/i.test(result.caiClaims.recorder)) {
            const hasStoreActivity = result.contentRecord.editsAndActivity.some((entry) => /store/i.test(String(entry)));
            if (!hasStoreActivity) {
                result.contentRecord.editsAndActivity.push('Store');
            }
        }

        if (!result.contentRecord.producer) {
            result.contentRecord.producer =
                result.structuredMetadata.display ||
                result.structuredMetadata.copyright ||
                result.structuredMetadata.Copyright ||
                null;
        }

        if (result.certificates.length > 0) {
            const certificate = result.certificates[0];
            result.contentRecord.identifiedBy = this.getCertificateEntity(certificate.info.subject);
            result.contentRecord.signedBy = this.getCertificateEntity(certificate.info.issuer);
        }

        result.hasCAI =
            result.assertions.length > 0 ||
            Object.keys(result.caiClaims).length > 0 ||
            (result.xmpData && /cai|jumbf/i.test(result.xmpData.raw));
    }

    normalizeAssertionLabel(label, payload) {
        if (label !== 'cai.assertions' || !payload || typeof payload !== 'object' || Array.isArray(payload)) {
            return label;
        }

        if ('copyright' in payload || 'license' in payload || 'usage' in payload) {
            return 'cai.rights';
        }
        if ('display' in payload || 'uri' in payload || 'creator' in payload) {
            return 'cai.identity';
        }

        return label;
    }

    applyClaimPayload(payload, result) {
        if (!payload || typeof payload !== 'object') {
            return;
        }

        if (Array.isArray(payload.assertions)) {
            result.caiClaims.assertionsList = payload.assertions.map((reference) => this.parseAssertionReference(reference));
        }

        if (Array.isArray(payload.asset_hashes)) {
            result.caiClaims.assetHashes = payload.asset_hashes.map((hash) => ({
                name: hash.name || null,
                value: hash.value || null,
                start: hash.start || null,
                length: hash.length || null,
                algorithm: this.detectHashAlgorithm(hash.value)
            }));
        }

        if (payload.recorder) {
            result.caiClaims.recorder = payload.recorder;
            result.structuredMetadata.recorder = payload.recorder;
        }

        if (payload.signature) {
            result.caiClaims.signatureReference = payload.signature;
        }

        result.caiClaims.claim = payload;
    }

    parseAssertionReference(reference) {
        const clean = String(reference);
        const typeMatch = clean.match(/\/(cai\.[^/?]+|adobe\.[^/?]+|starling\.[^/?]+)(?:\?|$)/);
        const hashMatch = clean.match(/[?&]hl=([^&]+)/);

        return {
            fullReference: clean,
            type: typeMatch ? typeMatch[1] : 'unknown',
            hash: hashMatch ? hashMatch[1] : null
        };
    }

    formatActionEntry(entry) {
        if (!entry || typeof entry !== 'object') {
            return String(entry);
        }

        const action = entry['stEvt:action'] || entry.action || 'unknown';
        const parameters = entry['stEvt:parameters'] || entry.parameters;
        const software = entry['stEvt:softwareAgent'] || entry.softwareAgent;
        const when = entry['stEvt:when'] || entry.when;

        const parts = [action];
        if (parameters) {
            parts.push(parameters);
        }
        if (software) {
            parts.push(`via ${software}`);
        }
        if (when) {
            parts.push(`at ${when}`);
        }

        return parts.join(' | ');
    }

    detectHashAlgorithm(hashValue) {
        if (!hashValue) {
            return 'unknown';
        }
        if (/^[A-Fa-f0-9]{64}$/.test(hashValue)) {
            return 'SHA-256';
        }
        if (/^[A-Fa-f0-9]{40}$/.test(hashValue)) {
            return 'SHA-1';
        }
        if (/^m[Ee][A-Za-z0-9+/=]+$/.test(hashValue)) {
            return 'multihash';
        }
        return 'unknown';
    }

    getCertificateEntity(nameInfo) {
        if (!nameInfo) {
            return null;
        }
        if (nameInfo.CN) {
            return nameInfo.CN;
        }
        if (nameInfo.O) {
            return nameInfo.O;
        }
        const summary = this.formatDistinguishedName(nameInfo);
        return summary || null;
    }

    async parsePGPPublicKey(armoredKey) {
        try {
            const normalized = this.normalizePGPArmor(armoredKey);
            const bytes = this.decodePGPArmor(normalized);
            if (!bytes || bytes.length === 0) {
                return null;
            }

            const packets = this.readOpenPGPPackets(bytes);
            const info = {
                userIds: [],
                subkeys: []
            };

            for (const packet of packets) {
                if (packet.tag === 6) {
                    const parsed = await this.parseOpenPGPPublicKeyPacket(packet.body);
                    if (parsed) {
                        info.fingerprint = parsed.fingerprint || null;
                        info.keyId = parsed.keyId || null;
                        info.algorithm = parsed.algorithm || null;
                        info.bits = parsed.bits || null;
                        info.created = parsed.created || null;
                    }
                } else if (packet.tag === 13) {
                    info.userIds.push(this.textDecoder.decode(packet.body));
                } else if (packet.tag === 14) {
                    const parsedSubkey = await this.parseOpenPGPPublicKeyPacket(packet.body);
                    if (parsedSubkey) {
                        info.subkeys.push(parsedSubkey);
                    }
                }
            }

            return Object.keys(info).length > 0 ? info : null;
        } catch {
            return null;
        }
    }

    normalizePGPArmor(block) {
        if (!block) {
            return '';
        }

        const begin = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
        const end = '-----END PGP PUBLIC KEY BLOCK-----';
        const start = block.indexOf(begin);
        const finish = block.indexOf(end);
        if (start < 0 || finish < 0) {
            return block;
        }

        let body = block.slice(start + begin.length, finish).replace(/\s+/g, '');
        body = body.replace(/^Version:[^m]+/, '');

        let checksum = '';
        const crcMatch = body.match(/([A-Za-z0-9+/]+={0,2})([A-Za-z0-9+/]{4})$/);
        if (crcMatch && crcMatch[1].endsWith('==')) {
            body = crcMatch[1];
            checksum = crcMatch[2];
        }

        const lines = [begin, ''];
        for (let i = 0; i < body.length; i += 64) {
            lines.push(body.slice(i, i + 64));
        }
        if (checksum) {
            lines.push(`=${checksum}`);
        }
        lines.push(end, '');
        return lines.join('\n');
    }

    decodePGPArmor(armored) {
        const base64 = armored
            .split('\n')
            .filter((line) => line && !line.startsWith('-----') && !line.startsWith('=') && !line.includes(':'))
            .join('');

        return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
    }

    readOpenPGPPackets(bytes) {
        const packets = [];
        let offset = 0;

        while (offset < bytes.length) {
            const header = bytes[offset];
            if ((header & 0x80) === 0) {
                break;
            }

            let tag;
            let lengthInfo;
            if (header & 0x40) {
                tag = header & 0x3F;
                lengthInfo = this.readNewPacketLength(bytes, offset + 1);
                if (!lengthInfo) break;
                const bodyStart = offset + 1 + lengthInfo.headerBytes;
                packets.push({ tag, body: bytes.slice(bodyStart, bodyStart + lengthInfo.length) });
                offset = bodyStart + lengthInfo.length;
            } else {
                tag = (header >> 2) & 0x0F;
                lengthInfo = this.readOldPacketLength(bytes, offset + 1, header & 0x03);
                if (!lengthInfo) break;
                const bodyStart = offset + 1 + lengthInfo.headerBytes;
                packets.push({ tag, body: bytes.slice(bodyStart, bodyStart + lengthInfo.length) });
                offset = bodyStart + lengthInfo.length;
            }
        }

        return packets;
    }

    readNewPacketLength(bytes, offset) {
        if (offset >= bytes.length) return null;
        const first = bytes[offset];
        if (first < 192) {
            return { length: first, headerBytes: 1 };
        }
        if (first < 224) {
            if (offset + 1 >= bytes.length) return null;
            return {
                length: ((first - 192) << 8) + bytes[offset + 1] + 192,
                headerBytes: 2
            };
        }
        if (first === 255) {
            if (offset + 4 >= bytes.length) return null;
            return {
                length: ((bytes[offset + 1] << 24) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 8) | bytes[offset + 4]) >>> 0,
                headerBytes: 5
            };
        }
        return null;
    }

    readOldPacketLength(bytes, offset, lengthType) {
        if (lengthType === 0) {
            return { length: bytes[offset], headerBytes: 1 };
        }
        if (lengthType === 1) {
            return { length: (bytes[offset] << 8) | bytes[offset + 1], headerBytes: 2 };
        }
        if (lengthType === 2) {
            return {
                length: ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0,
                headerBytes: 4
            };
        }
        return null;
    }

    async parseOpenPGPPublicKeyPacket(body) {
        if (!body || body.length < 6) {
            return null;
        }

        const version = body[0];
        if (version !== 4) {
            return null;
        }

        const createdSeconds = ((body[1] << 24) | (body[2] << 16) | (body[3] << 8) | body[4]) >>> 0;
        const algorithmId = body[5];
        const algorithm = this.getOpenPGPAlgorithmName(algorithmId);
        let bits = null;

        if ([1, 2, 3].includes(algorithmId) && body.length >= 8) {
            bits = (body[6] << 8) | body[7];
        }

        let fingerprint = null;
        let keyId = null;
        const subtle = globalThis.crypto && globalThis.crypto.subtle;
        if (subtle && body.length <= 0xFFFF) {
            const fingerprintInput = new Uint8Array(body.length + 3);
            fingerprintInput[0] = 0x99;
            fingerprintInput[1] = (body.length >> 8) & 0xFF;
            fingerprintInput[2] = body.length & 0xFF;
            fingerprintInput.set(body, 3);
            const digest = new Uint8Array(await subtle.digest('SHA-1', fingerprintInput));
            fingerprint = this.bytesToHex(digest).toUpperCase();
            keyId = fingerprint.slice(-16);
        }

        return {
            fingerprint,
            keyId,
            algorithm,
            bits,
            created: new Date(createdSeconds * 1000).toISOString()
        };
    }

    getOpenPGPAlgorithmName(id) {
        const names = {
            1: 'RSA',
            2: 'RSA Encrypt-Only',
            3: 'RSA Sign-Only',
            16: 'ElGamal',
            17: 'DSA',
            18: 'ECDH',
            19: 'ECDSA',
            22: 'EdDSA'
        };
        return names[id] || `Algorithm ${id}`;
    }

    extractCertificates(bytes) {
        const certificates = [];
        const seen = new Set();

        for (let offset = 0; offset < bytes.length - 8; offset += 1) {
            if (bytes[offset] !== 0x30) {
                continue;
            }

            const certificate = this.tryParseCertificate(bytes, offset);
            if (!certificate) {
                continue;
            }

            const key = `${certificate.offset}:${certificate.length}`;
            if (seen.has(key)) {
                continue;
            }
            seen.add(key);
            certificates.push(certificate);
            offset += Math.max(0, certificate.length - 1);
        }

        return certificates;
    }

    tryParseCertificate(bytes, offset) {
        const outer = this.readASN1(bytes, offset);
        if (!outer || outer.tag !== 0x30) {
            return null;
        }

        let children;
        try {
            children = this.readASN1Children(bytes, outer.contentStart, outer.end);
        } catch {
            return null;
        }

        if (children.length < 3) {
            return null;
        }
        if (children[0].tag !== 0x30 || children[1].tag !== 0x30 || children[2].tag !== 0x03) {
            return null;
        }

        const info = this.parseCertificateInfo(bytes, children[0]);
        if (!info.subject && !info.issuer) {
            return null;
        }

        const certBytes = bytes.slice(offset, outer.end);
        const base64 = this.arrayBufferToBase64(certBytes);

        return {
            offset,
            length: outer.end - offset,
            base64,
            pem: this.formatAsPEM(base64),
            info
        };
    }

    parseCertificateInfo(bytes, tbsNode) {
        const info = {
            issuer: null,
            subject: null,
            validFrom: null,
            validTo: null,
            serialNumber: null,
            algorithm: null
        };

        const fields = this.readASN1Children(bytes, tbsNode.contentStart, tbsNode.end);
        let index = 0;

        if (fields[index] && fields[index].tagClass === 2 && fields[index].tagNumber === 0) {
            index += 1;
        }

        if (fields[index]) {
            info.serialNumber = this.bytesToHex(bytes.slice(fields[index].contentStart, fields[index].end));
            index += 1;
        }

        if (fields[index] && fields[index].tag === 0x30) {
            info.algorithm = this.parseAlgorithmIdentifier(bytes, fields[index]);
            index += 1;
        }

        if (fields[index] && fields[index].tag === 0x30) {
            info.issuer = this.parseDistinguishedName(bytes, fields[index]);
            index += 1;
        }

        if (fields[index] && fields[index].tag === 0x30) {
            const validity = this.parseValidity(bytes, fields[index]);
            info.validFrom = validity.validFrom;
            info.validTo = validity.validTo;
            index += 1;
        }

        if (fields[index] && fields[index].tag === 0x30) {
            info.subject = this.parseDistinguishedName(bytes, fields[index]);
        }

        return info;
    }

    parseAlgorithmIdentifier(bytes, node) {
        const children = this.readASN1Children(bytes, node.contentStart, node.end);
        if (!children[0] || children[0].tag !== 0x06) {
            return null;
        }
        const oid = this.decodeOID(bytes.slice(children[0].contentStart, children[0].end));
        return this.algorithmOidMap[oid] || oid;
    }

    parseValidity(bytes, node) {
        const children = this.readASN1Children(bytes, node.contentStart, node.end);
        return {
            validFrom: children[0] ? this.parseASN1Time(bytes, children[0]) : null,
            validTo: children[1] ? this.parseASN1Time(bytes, children[1]) : null
        };
    }

    parseDistinguishedName(bytes, node) {
        const info = {};
        const sets = this.readASN1Children(bytes, node.contentStart, node.end);

        sets.forEach((setNode) => {
            if (setNode.tag !== 0x31) {
                return;
            }
            const sequences = this.readASN1Children(bytes, setNode.contentStart, setNode.end);
            sequences.forEach((sequenceNode) => {
                if (sequenceNode.tag !== 0x30) {
                    return;
                }
                const parts = this.readASN1Children(bytes, sequenceNode.contentStart, sequenceNode.end);
                if (parts.length < 2 || parts[0].tag !== 0x06) {
                    return;
                }
                const oid = this.decodeOID(bytes.slice(parts[0].contentStart, parts[0].end));
                const key = this.attributeOidMap[oid] || oid;
                const value = this.decodeASN1String(bytes, parts[1]);
                if (value) {
                    info[key] = value;
                }
            });
        });

        return Object.keys(info).length > 0 ? info : null;
    }

    formatDistinguishedName(nameInfo) {
        if (!nameInfo) {
            return '';
        }

        const order = ['CN', 'OU', 'O', 'L', 'ST', 'C'];
        const rendered = [];

        order.forEach((key) => {
            if (nameInfo[key]) {
                rendered.push(`${key}=${nameInfo[key]}`);
            }
        });

        Object.keys(nameInfo).forEach((key) => {
            if (!order.includes(key)) {
                rendered.push(`${key}=${nameInfo[key]}`);
            }
        });

        return rendered.join(', ');
    }

    readASN1(bytes, offset) {
        if (offset >= bytes.length) {
            return null;
        }

        const tag = bytes[offset];
        if (offset + 1 >= bytes.length) {
            return null;
        }

        const lengthInfo = this.readASN1Length(bytes, offset + 1);
        if (!lengthInfo) {
            return null;
        }

        const headerLength = 1 + lengthInfo.bytesRead;
        const contentStart = offset + headerLength;
        const end = contentStart + lengthInfo.length;

        if (end > bytes.length) {
            return null;
        }

        return {
            tag,
            tagClass: (tag & 0xC0) >> 6,
            constructed: (tag & 0x20) !== 0,
            tagNumber: tag & 0x1F,
            offset,
            headerLength,
            contentStart,
            end,
            length: lengthInfo.length
        };
    }

    readASN1Length(bytes, offset) {
        if (offset >= bytes.length) {
            return null;
        }

        const first = bytes[offset];
        if ((first & 0x80) === 0) {
            return {
                length: first,
                bytesRead: 1
            };
        }

        const count = first & 0x7F;
        if (count === 0 || count > 4 || offset + count >= bytes.length) {
            return null;
        }

        let length = 0;
        for (let i = 0; i < count; i += 1) {
            length = (length << 8) | bytes[offset + 1 + i];
        }

        return {
            length,
            bytesRead: 1 + count
        };
    }

    readASN1Children(bytes, start, end) {
        const children = [];
        let offset = start;

        while (offset < end) {
            const child = this.readASN1(bytes, offset);
            if (!child || child.end > end || child.end <= offset) {
                throw new Error('Invalid ASN.1 child node.');
            }
            children.push(child);
            offset = child.end;
        }

        return children;
    }

    decodeOID(bytes) {
        if (!bytes || bytes.length === 0) {
            return '';
        }

        const first = bytes[0];
        const parts = [Math.floor(first / 40), first % 40];
        let value = 0;

        for (let i = 1; i < bytes.length; i += 1) {
            value = (value << 7) | (bytes[i] & 0x7F);
            if ((bytes[i] & 0x80) === 0) {
                parts.push(value);
                value = 0;
            }
        }

        return parts.join('.');
    }

    decodeASN1String(bytes, node) {
        const raw = bytes.slice(node.contentStart, node.end);
        switch (node.tag) {
            case 0x0C:
            case 0x13:
            case 0x14:
            case 0x16:
            case 0x1A:
            case 0x1E:
                return this.textDecoder.decode(raw).replace(/\0+$/g, '').trim();
            default:
                return this.textDecoder.decode(raw).replace(/\0+$/g, '').trim();
        }
    }

    parseASN1Time(bytes, node) {
        const text = this.textDecoder.decode(bytes.slice(node.contentStart, node.end)).trim();
        if (node.tag === 0x17) {
            return this.parseUTCTime(text);
        }
        if (node.tag === 0x18) {
            return this.parseGeneralizedTime(text);
        }
        return text || null;
    }

    parseUTCTime(text) {
        const match = text.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
        if (!match) {
            return text;
        }

        const year = Number(match[1]);
        const fullYear = year >= 50 ? 1900 + year : 2000 + year;
        return `${fullYear}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}Z`;
    }

    parseGeneralizedTime(text) {
        const match = text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
        if (!match) {
            return text;
        }
        return `${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}Z`;
    }

    arrayBufferToBase64(buffer) {
        let binary = '';
        buffer.forEach((byte) => {
            binary += String.fromCharCode(byte);
        });
        return btoa(binary);
    }

    formatAsPEM(base64) {
        const lines = ['-----BEGIN CERTIFICATE-----'];
        for (let i = 0; i < base64.length; i += 64) {
            lines.push(base64.slice(i, i + 64));
        }
        lines.push('-----END CERTIFICATE-----');
        return lines.join('\n');
    }

    readUInt16(data, offset, byteOrder) {
        if (byteOrder === 'LE') {
            return data[offset] | (data[offset + 1] << 8);
        }
        return (data[offset] << 8) | data[offset + 1];
    }

    readUInt32(data, offset, byteOrder) {
        if (byteOrder === 'LE') {
            return (
                data[offset] |
                (data[offset + 1] << 8) |
                (data[offset + 2] << 16) |
                (data[offset + 3] << 24)
            ) >>> 0;
        }
        return (
            (data[offset] << 24) |
            (data[offset + 1] << 16) |
            (data[offset + 2] << 8) |
            data[offset + 3]
        ) >>> 0;
    }

    readUIntArray(data, offset, count, size, byteOrder) {
        const values = [];
        for (let i = 0; i < count; i += 1) {
            values.push(size === 2
                ? this.readUInt16(data, offset + (i * size), byteOrder)
                : this.readUInt32(data, offset + (i * size), byteOrder));
        }
        return values;
    }

    readRational(data, offset, byteOrder, signed) {
        const numerator = signed ? this.readInt32(data, offset, byteOrder) : this.readUInt32(data, offset, byteOrder);
        const denominator = signed ? this.readInt32(data, offset + 4, byteOrder) : this.readUInt32(data, offset + 4, byteOrder);
        if (!denominator) {
            return 0;
        }
        return numerator / denominator;
    }

    readRationalArray(data, offset, count, byteOrder, signed) {
        const values = [];
        for (let i = 0; i < count; i += 1) {
            values.push(this.readRational(data, offset + (i * 8), byteOrder, signed));
        }
        return values;
    }

    readInt32(data, offset, byteOrder) {
        const value = this.readUInt32(data, offset, byteOrder);
        return value > 0x7FFFFFFF ? value - 0x100000000 : value;
    }

    bytesToHex(bytes) {
        return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, '0')).join('');
    }

    sanitizeText(text) {
        return text.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]+/g, ' ');
    }

    getSummary(result) {
        const summary = {
            hasCAI: result.hasCAI,
            dataTypes: [],
            assertionCount: result.assertions.length,
            claimCount: Object.keys(result.caiClaims).length,
            fileSize: result.fileInfo.size,
            errors: result.errors.length
        };

        if (result.xmpData) {
            summary.dataTypes.push('XMP');
        }
        if (result.exifData) {
            summary.dataTypes.push('EXIF');
        }
        if (result.jumbfBoxes.length > 0) {
            summary.dataTypes.push('JUMBF');
        }
        if (result.certificates.length > 0) {
            summary.dataTypes.push('X.509');
        }

        return summary;
    }
}

if (typeof window !== 'undefined') {
    window.JUMBFParser = JUMBFParser;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = JUMBFParser;
}
