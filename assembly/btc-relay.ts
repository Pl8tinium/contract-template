import { db, Arrays, SystemAPI, Crypto } from '@vsc.eco/sdk/assembly';
import { JSON, JSONEncoder } from "assemblyscript-json/assembly";
import { BigInt } from "as-bigint/assembly"
// import { toHexString, fromHexString } from '@vsc.eco/sdk/assembly/common/arrays';

const DIFF_ONE_TARGET = BigInt.fromString('0xffff0000000000000000000000000000000000000000000000000000');

const validity_depth: i32 = 2;

const headersState: Map<string, Map<i64, string>> = new Map<string, Map<i64, string>>();

// pla: for serialization and storage in the db, we convert BigInt to string and Uint8Array to hex string
class Header {
    prevBlock: Uint8Array;
    timestamp: string;
    merkleRoot: Uint8Array;
    diff: BigInt;
    totalDiff: BigInt;
    height: i32;
    raw: string;

    constructor(
        prevBlock: Uint8Array,
        timestamp: string,
        merkleRoot: Uint8Array,
        diff: BigInt,
        totalDiff: BigInt,
        height: i32,
        raw: string
    ) {
        this.prevBlock = prevBlock;
        this.timestamp = timestamp;
        this.merkleRoot = merkleRoot;
        this.diff = diff;
        this.totalDiff = totalDiff;
        this.height = height;
        this.raw = raw;
    }

    stringify(): string {
        let encoder = new JSONEncoder();
        encoder.pushObject(null);
        encoder.setString("prevBlock", toHexString(this.prevBlock));
        encoder.setString("timestamp", this.timestamp);
        encoder.setString("merkleRoot", toHexString(this.merkleRoot));
        encoder.setString("diff", this.diff.toString());
        encoder.setString("totalDiff", this.totalDiff.toString());
        encoder.setInteger("height", this.height);
        encoder.setString("raw", this.raw);
        encoder.popObject();
        return encoder.toString();
    }
}

/**
 * Convert the string `hex` which must consist of an even number of
 * hexadecimal digits to a `Uint8Array`. The string `hex` can optionally
 * start with '0x'
 */
export function fromHexString(hex: string): Uint8Array {
    //   System.require(hex.length % 2 == 0, 'input ' + hex + ' has odd length');
    // Skip possible `0x` prefix.
    if (hex.length >= 2 && hex.charAt(0) == '0' && hex.charAt(1) == 'x') {
        hex = hex.substr(2);
    }
    let output = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        output[i / 2] = U8.parseInt(hex.substr(i, 2), 16);
    }
    return output;
}

/**
 * Convert the Uint8Array `buffer` into a hexadecimal digits string. The string can optionally
 * be appended with '0x'
 */
export function toHexString(buffer: Uint8Array, prepend0x: bool = false): string {
    let output = '';

    if (prepend0x) {
        output += '0x';
    }

    for (let i = 0; i < buffer.length; i += 1) {
        output += `0${buffer[i].toString(16)}`.slice(-2);
    }

    return output;
}

function getStringFromJSON(jsonObject: JSON.Obj, key: string): string {
    let extractedValue: JSON.Str | null = jsonObject.getString(key);
    if (extractedValue != null) {
        return extractedValue.valueOf();
    }

    return "";
}

function getIntFromJSON(jsonObject: JSON.Obj, key: string): i64 {
    let extractedValue: JSON.Integer | null = jsonObject.getInteger(key);
    if (extractedValue != null) {
        return extractedValue.valueOf();
    }

    return 0;
}

export function getPreheaders(): Map<string, Header> {
    let parsed = <JSON.Obj>JSON.parse(db.getObject(`pre-headers/main`));
    const preheaders: Map<string, Header> = new Map<string, Header>();

    for (let i = 0; i < parsed.keys.length; ++i) {
        let key = parsed.keys[i];
        let obj = parsed.get(key);
        if (obj instanceof JSON.Obj) {
            let preheader = new Header(
                fromHexString(getStringFromJSON(<JSON.Obj>obj, "prevBlock")),
                getStringFromJSON(<JSON.Obj>obj, "timestamp"),
                fromHexString(getStringFromJSON(<JSON.Obj>obj, "merkleRoot")),
                BigInt.from(getStringFromJSON(<JSON.Obj>obj, "diff")),
                BigInt.from(getStringFromJSON(<JSON.Obj>obj, "totalDiff")),
                getIntFromJSON(<JSON.Obj>obj, "height") as i32,
                getStringFromJSON(<JSON.Obj>obj, "raw")
            );
            preheaders.set(key, preheader);
        }
    }

    return preheaders;
}

export function reverseEndianness(uint8Arr: Uint8Array): Uint8Array {
    const buf = new Uint8Array(uint8Arr.length);
    buf.set(uint8Arr.reverse())
    return buf;
}

export function sha256(param: Uint8Array): Uint8Array {
    const arg0Value: string = Arrays.toHexString(param, false);

    const obj = new JSON.Obj()
    obj.set('arg0', arg0Value)

    const result = <JSON.Obj>JSON.parse(SystemAPI.call('crypto.sha256', obj.stringify()))
    if (result.getString('result')!.isString) {
        return Arrays.fromHexString(result.getString('result')!.valueOf()!)
    } else {
        //Never should happen
        throw new Error('Crypto - incorrect binding response')
    }
}

export function extractPrevBlockLE(header: Uint8Array): Uint8Array {
    return header.slice(4, 36);
}

export function validateHeaderPrevHashLE(header: Uint8Array, prevHeaderDigest: Uint8Array): boolean {
    // Extract prevHash of current header
    const prevHashLE = extractPrevBlockLE(header);

    // Compare prevHash of current header to previous header's digest
    if (!typedArraysAreEqual(prevHashLE, prevHeaderDigest)) {
        return false;
    }

    return true;
}

export function bytesToUint(uint8Arr: Uint8Array): i64 {
    let total: i64 = 0;
    for (let i = 0; i < uint8Arr.length; i += 1) {
        total += <u64>uint8Arr[i] << ((<u64>uint8Arr.length - i - 1) * 8);
    }
    return total;
}

// pla: return type probably not right
// * Target is a 256 bit number encoded as a 3-byte mantissa
// * and 1 byte exponent
export function extractTarget(header: Uint8Array): BigInt {
    const m: Uint8Array = header.slice(72, 75);
    const e: i8 = header[75];

    const mantissa: i64 = bytesToUint(reverseEndianness(m));

    const exponent: i8 = e - 3;

    const power: BigInt = BigInt.from(256).pow(exponent);

    return power.mul(BigInt.from(mantissa));
}

// Implements bitcoin's hash256 (double sha2)
export function hash256(preImage: Uint8Array): Uint8Array {
    return sha256(sha256(preImage));
}

export function validateHeaderWork(digest: Uint8Array, target: BigInt): boolean {
    if (typedArraysAreEqual(digest, new Uint8Array(32))) {
        return false;
    }

    const uInt: i64 = bytesToUint(reverseEndianness(digest));

    return target.gt(uInt);
}

export function typedArraysAreEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
        throw new Error('Arrays must be of type Uint8Array');
    }

    if (a.byteLength !== b.byteLength) return false;
    for (let i = 0; i < a.byteLength; i += 1) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

export function calculateDifficulty(target: BigInt): BigInt {
    return DIFF_ONE_TARGET.div(target);
}

export function validateHeaderChain(headers: Uint8Array): BigInt {
    if (headers.length % 80 !== 0) {
        throw new Error('Header bytes not multiple of 80.');
    }

    let digest: Uint8Array = new Uint8Array(0);
    let totalDifficulty: BigInt = BigInt.from(0);

    for (let i = 0; i < headers.length / 80; i += 1) {
        // ith header start index and ith header
        const start = i * 80;
        const header = headers.slice(start, start + 80);

        // After the first header, check that headers are in a chain
        if (i !== 0) {
            if (!validateHeaderPrevHashLE(header, digest)) {
                throw new Error('Header bytes not a valid chain.');
            }
        }

        // ith header target
        const target = extractTarget(header);


        // Require that the header has sufficient work
        digest = hash256(header);
        if (!validateHeaderWork(digest, target)) {
            throw new Error('Header does not meet its own difficulty target.');
        }

        totalDifficulty = totalDifficulty.add(calculateDifficulty(target));
    }

    return totalDifficulty;
}

export function extractTimestampLE(header: Uint8Array): Uint8Array {
    return header.slice(68, 72);
}

export function extractTimestamp(header: Uint8Array): i64 {
    return bytesToUint(reverseEndianness(extractTimestampLE(header)));
}

export function isZeroFilled(block: Uint8Array): bool {
    for (let i = 0, k = block.length; i < k; ++i) {
        if (block[i] !== 0) return false;
    }
    return true;
}

export function sortPreheadersByTotalDiff(preheaders: Map<string, Header>): Array<Header> {
    // Convert Map to an Array of values with their keys
    let entries: Array<Header> = [];
    let keys = preheaders.keys();
    for (let i = 0, k = keys.length; i < k; ++i) {
        let key = unchecked(keys[i]); // Access keys with unchecked for performance when bounds are known
        let value = preheaders.get(key);
        if (value) {
            entries.push(value);
        }
    }

    // Sort the array using a comparator function
    entries.sort((a: Header, b: Header): i32 => {
        if (a.totalDiff > b.totalDiff) return 1;
        if (a.totalDiff < b.totalDiff) return -1;
        return 0;
    });

    return entries;
}

export function calcKey(height: i32): string {
    const cs: i32 = 100;
    // pla: is math.floor needed?
    // const keyA: i32 = Mathf.floor(height / cs) * cs;
    const keyA: i32 = (height / cs) * cs;

    return keyA.toString() + "-" + (keyA + cs).toString();
}

export function processHeaders(headers: Array<string>): void {
    const preheaders = getPreheaders();

    for (let i = 0; i < headers.length; ++i) {
        let rawBH = headers[i];
        const decodeHex = Arrays.fromHexString(rawBH);
        const extractedPrevBlockLE = extractPrevBlockLE(decodeHex);
        const prevBlock = reverseEndianness(extractedPrevBlockLE);
        const timestamp = extractTimestamp(decodeHex);
        const merkleRoot = reverseEndianness(decodeHex.slice(36, 68));
        const headerHash = hash256(decodeHex);
        const diff = validateHeaderChain(decodeHex);

        // Wip
        let prevDiff: BigInt = BigInt.from(0);
        let prevHeight: i32 = 0;

        const prevBlockStr = toHexString(prevBlock)
        let continueLoop: bool = true;

        if (prevBlockStr === '0000000000000000000000000000000000000000000000000000000000000000') {
            prevHeight = -1;
        } else {
            let blockInfo = preheaders.get(prevBlockStr);
            if (blockInfo) {
                prevDiff = blockInfo.totalDiff;
                prevHeight = blockInfo.height as i32;
            } else {
                // pla: because assemblyscript doesnt support 'continue;'
                continueLoop = false;
            }
        }

        if (continueLoop) {
            const decodedHeader = new Header(
                prevBlock,
                new Date(timestamp * 1000).toISOString(),
                merkleRoot,
                diff,
                diff.add(prevDiff),
                prevHeight + 1,
                rawBH
            );

            preheaders.set(toHexString(reverseEndianness(headerHash)), decodedHeader);
        }
    }

    let sortedPreheaders: Array<Header> = sortPreheadersByTotalDiff(preheaders);

    const topHeader: Header = sortedPreheaders[sortedPreheaders.length - 1];

    let blocksToPush: Array<Header> = [];
    let curDepth: i32 = 0;
    let prevBlock: Uint8Array | null = null;

    while (true) {
        if (!prevBlock) {
            prevBlock = topHeader.prevBlock;
        }

        let currentHeader = preheaders.get(toHexString(prevBlock));
        if (currentHeader) {
            if (curDepth > validity_depth) {
                blocksToPush.push(currentHeader);
            } else {
                curDepth = curDepth + 1;
            }
        } else {
            break;
        }

        prevBlock = currentHeader.prevBlock;
    }

    let highestHeight = 0;
    for (let i = 0, k = blocksToPush.length; i < k; ++i) {
        let block = blocksToPush[i];
        let key = calcKey(block.height);
        //Get headers in memory if not available
        if (!headersState.has(key)) {
            const parsed = <JSON.Obj>JSON.parse(db.getObject(`headers/${key}`));
            const pulledHeaders: Map<i64, string> | null = new Map<i64, string>();
            for (let i = 0; i < parsed.keys.length; ++i) {
                let key = parsed.keys[i];
                let blockRaw = getStringFromJSON(<JSON.Obj>parsed, key);
                let height = parseInt(key) as i64;
                pulledHeaders.set(height, blockRaw);
            }
            headersState.set(key, pulledHeaders);
        }

        //Only override if not
        let stateForKey = headersState.get(key);
        if (stateForKey && !stateForKey.has(block.height)) {
            stateForKey.set(block.height, block.raw);
        }

        if (highestHeight < block.height) {
            highestHeight = block.height;
        }
    }

    let preHeaderKeys = preheaders.keys();
    for (let i = 0, k = preHeaderKeys.length; i < k; ++i) {
        let key = unchecked(preHeaderKeys[i]);
        let value = preheaders.get(key);
        if (value && highestHeight >= value.height) {
            preheaders.delete(unchecked(key));
        }
    }

    let headerStateKeys = headersState.keys();
    for (let i = 0, k = headerStateKeys.length; i < k; ++i) {
        let key = unchecked(headerStateKeys[i]);
        let val = headersState.get(key);
        if (val) {
            const serializedHeaderState = serializeHeaderState(val);
            db.setObject(`headers/${key}`, serializedHeaderState);
        }
    }

    db.setObject(`pre-headers/main`, serializePreHeaders(preheaders));
}

function serializePreHeaders(preheaders: Map<string, Header>): string {
    let encoder = new JSONEncoder();
    encoder.pushObject(null);

    let keys = preheaders.keys();
    for (let i = 0, k = keys.length; i < k; ++i) {
        let key = unchecked(keys[i]);
        let value = preheaders.get(key);
        if (value !== null) {
            encoder.setString(key, value.stringify());
        }
    }
    encoder.popObject();

    return encoder.toString();
}

function serializeHeaderState(headerState: Map<i64, string>): string {
    let encoder = new JSONEncoder();
    encoder.pushObject(null);

    let keys = headerState.keys();
    for (let i = 0, k = keys.length; i < k; ++i) {
        let key = unchecked(keys[i]);
        let value = headerState.get(key);
        if (value !== null) {
            encoder.setString(key.toString(), value);
        }
    }
    encoder.popObject();

    return encoder.toString();
}
