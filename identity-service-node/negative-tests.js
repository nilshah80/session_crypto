"use strict";
/**
 * Comprehensive Negative Test Suite for /v1/session/init endpoint
 *
 * Test Categories:
 * - Replay Protection
 * - Header Validation
 * - Public Key Validation
 * - TTL Validation
 * - Request Body Validation
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = __importStar(require("crypto"));
var http = __importStar(require("http"));
// Configuration
var BASE_URL = 'localhost';
var PORT = 3001;
var ENDPOINT = '/v1/session/init';
// Test utilities
function generateIdempotencyKey() {
    var timestamp = Date.now();
    var nonce = crypto.randomBytes(16).toString('hex');
    return { timestamp: timestamp, nonce: nonce, key: "".concat(timestamp, ".").concat(nonce) };
}
function generateECDHKeyPair() {
    var ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    var publicKey = ecdh.getPublicKey().toString('base64');
    return { publicKey: publicKey, ecdh: ecdh };
}
function makeSessionInitRequest(clientPublicKey, idempotencyKey, clientId, ttlSec) {
    return __awaiter(this, void 0, void 0, function () {
        var requestBody, bodyString, options;
        return __generator(this, function (_a) {
            requestBody = { clientPublicKey: clientPublicKey };
            if (ttlSec !== undefined) {
                requestBody.ttlSec = ttlSec;
            }
            bodyString = JSON.stringify(requestBody);
            options = {
                hostname: BASE_URL,
                port: PORT,
                path: ENDPOINT,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(bodyString),
                    'X-Idempotency-Key': idempotencyKey,
                    'X-ClientId': clientId,
                },
            };
            return [2 /*return*/, new Promise(function (resolve, reject) {
                    var req = http.request(options, function (res) {
                        var data = '';
                        res.on('data', function (chunk) { data += chunk; });
                        res.on('end', function () {
                            try {
                                resolve({
                                    status: res.statusCode || 500,
                                    body: JSON.parse(data),
                                    headers: res.headers,
                                });
                            }
                            catch (e) {
                                resolve({
                                    status: res.statusCode || 500,
                                    body: data,
                                    headers: res.headers,
                                });
                            }
                        });
                    });
                    req.on('error', reject);
                    req.write(bodyString);
                    req.end();
                })];
        });
    });
}
function makeRawRequest(path, method, headers, body) {
    return __awaiter(this, void 0, void 0, function () {
        var options;
        return __generator(this, function (_a) {
            options = {
                hostname: BASE_URL,
                port: PORT,
                path: path,
                method: method,
                headers: headers,
            };
            return [2 /*return*/, new Promise(function (resolve, reject) {
                    var req = http.request(options, function (res) {
                        var data = '';
                        res.on('data', function (chunk) { data += chunk; });
                        res.on('end', function () {
                            try {
                                resolve({
                                    status: res.statusCode || 500,
                                    body: JSON.parse(data),
                                    headers: res.headers,
                                });
                            }
                            catch (e) {
                                resolve({
                                    status: res.statusCode || 500,
                                    body: data,
                                    headers: res.headers,
                                });
                            }
                        });
                    });
                    req.on('error', reject);
                    if (body) {
                        req.write(body);
                    }
                    req.end();
                })];
        });
    });
}
// Test Categories
function testReplayProtection() {
    return __awaiter(this, void 0, void 0, function () {
        var results, publicKey, idempotencyKey, clientId, res1, res2, error_1, publicKey, oldTimestamp, nonce, idempotencyKey, res, error_2, publicKey, futureTimestamp, nonce, idempotencyKey, res, error_3, publicKey, timestamp, shortNonce, idempotencyKey, res, error_4;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    results = [];
                    console.log('\n=== Replay Protection Tests ===\n');
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 4, , 5]);
                    publicKey = generateECDHKeyPair().publicKey;
                    idempotencyKey = generateIdempotencyKey().key;
                    clientId = 'test-replay-1';
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, idempotencyKey, clientId, 900)];
                case 2:
                    res1 = _a.sent();
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, idempotencyKey, clientId, 900)];
                case 3:
                    res2 = _a.sent();
                    results.push({
                        name: 'Reused idempotency key (nonce reuse)',
                        passed: res1.status === 200 && res2.status === 409,
                        expected: 'First: 200, Second: 409 (replay detected)',
                        actual: "First: ".concat(res1.status, ", Second: ").concat(res2.status),
                        error: res2.status !== 409 ? JSON.stringify(res2.body) : undefined,
                    });
                    return [3 /*break*/, 5];
                case 4:
                    error_1 = _a.sent();
                    results.push({
                        name: 'Reused idempotency key (nonce reuse)',
                        passed: false,
                        expected: 'First: 200, Second: 409',
                        actual: 'Exception thrown',
                        error: error_1.message,
                    });
                    return [3 /*break*/, 5];
                case 5:
                    _a.trys.push([5, 7, , 8]);
                    publicKey = generateECDHKeyPair().publicKey;
                    oldTimestamp = Date.now() - 400000;
                    nonce = crypto.randomBytes(16).toString('hex');
                    idempotencyKey = "".concat(oldTimestamp, ".").concat(nonce);
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, idempotencyKey, 'test-replay-2', 900)];
                case 6:
                    res = _a.sent();
                    results.push({
                        name: 'Timestamp too old (beyond 5 minute window)',
                        passed: res.status === 400,
                        expected: '400 (timestamp invalid)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 8];
                case 7:
                    error_2 = _a.sent();
                    results.push({
                        name: 'Timestamp too old (beyond 5 minute window)',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_2.message,
                    });
                    return [3 /*break*/, 8];
                case 8:
                    _a.trys.push([8, 10, , 11]);
                    publicKey = generateECDHKeyPair().publicKey;
                    futureTimestamp = Date.now() + 400000;
                    nonce = crypto.randomBytes(16).toString('hex');
                    idempotencyKey = "".concat(futureTimestamp, ".").concat(nonce);
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, idempotencyKey, 'test-replay-3', 900)];
                case 9:
                    res = _a.sent();
                    results.push({
                        name: 'Timestamp in future (beyond window)',
                        passed: res.status === 400,
                        expected: '400 (timestamp invalid)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 11];
                case 10:
                    error_3 = _a.sent();
                    results.push({
                        name: 'Timestamp in future (beyond window)',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_3.message,
                    });
                    return [3 /*break*/, 11];
                case 11:
                    _a.trys.push([11, 13, , 14]);
                    publicKey = generateECDHKeyPair().publicKey;
                    timestamp = Date.now();
                    shortNonce = crypto.randomBytes(4).toString('hex');
                    idempotencyKey = "".concat(timestamp, ".").concat(shortNonce);
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, idempotencyKey, 'test-replay-4', 900)];
                case 12:
                    res = _a.sent();
                    results.push({
                        name: 'Nonce too short (< 16 chars)',
                        passed: res.status === 400,
                        expected: '400 (nonce invalid)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 14];
                case 13:
                    error_4 = _a.sent();
                    results.push({
                        name: 'Nonce too short (< 16 chars)',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_4.message,
                    });
                    return [3 /*break*/, 14];
                case 14: return [2 /*return*/, results];
            }
        });
    });
}
function testHeaderValidation() {
    return __awaiter(this, void 0, void 0, function () {
        var results, publicKey, body, res, error_5, publicKey, idempotencyKey, body, res, error_6, publicKey, malformedKey, res, error_7, publicKey, nonce, malformedKey, res, error_8, publicKey, idempotencyKey, res, error_9;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    results = [];
                    console.log('\n=== Header Validation Tests ===\n');
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    publicKey = generateECDHKeyPair().publicKey;
                    body = JSON.stringify({ clientPublicKey: publicKey, ttlSec: 900 });
                    return [4 /*yield*/, makeRawRequest(ENDPOINT, 'POST', {
                            'Content-Type': 'application/json',
                            'Content-Length': Buffer.byteLength(body).toString(),
                            'X-ClientId': 'test-header-1',
                        }, body)];
                case 2:
                    res = _a.sent();
                    results.push({
                        name: 'Missing X-Idempotency-Key header',
                        passed: res.status === 400,
                        expected: '400 (missing header)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 4];
                case 3:
                    error_5 = _a.sent();
                    results.push({
                        name: 'Missing X-Idempotency-Key header',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_5.message,
                    });
                    return [3 /*break*/, 4];
                case 4:
                    _a.trys.push([4, 6, , 7]);
                    publicKey = generateECDHKeyPair().publicKey;
                    idempotencyKey = generateIdempotencyKey().key;
                    body = JSON.stringify({ clientPublicKey: publicKey, ttlSec: 900 });
                    return [4 /*yield*/, makeRawRequest(ENDPOINT, 'POST', {
                            'Content-Type': 'application/json',
                            'Content-Length': Buffer.byteLength(body).toString(),
                            'X-Idempotency-Key': idempotencyKey,
                        }, body)];
                case 5:
                    res = _a.sent();
                    results.push({
                        name: 'Missing X-ClientId header',
                        passed: res.status === 400,
                        expected: '400 (missing header)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 7];
                case 6:
                    error_6 = _a.sent();
                    results.push({
                        name: 'Missing X-ClientId header',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_6.message,
                    });
                    return [3 /*break*/, 7];
                case 7:
                    _a.trys.push([7, 9, , 10]);
                    publicKey = generateECDHKeyPair().publicKey;
                    malformedKey = 'invalid-format-without-dot';
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, malformedKey, 'test-header-3', 900)];
                case 8:
                    res = _a.sent();
                    results.push({
                        name: 'Malformed idempotency key (no dot separator)',
                        passed: res.status === 400,
                        expected: '400 (malformed key)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 10];
                case 9:
                    error_7 = _a.sent();
                    results.push({
                        name: 'Malformed idempotency key (no dot separator)',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_7.message,
                    });
                    return [3 /*break*/, 10];
                case 10:
                    _a.trys.push([10, 12, , 13]);
                    publicKey = generateECDHKeyPair().publicKey;
                    nonce = crypto.randomBytes(16).toString('hex');
                    malformedKey = "notanumber.".concat(nonce);
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, malformedKey, 'test-header-4', 900)];
                case 11:
                    res = _a.sent();
                    results.push({
                        name: 'Malformed idempotency key (non-numeric timestamp)',
                        passed: res.status === 400,
                        expected: '400 (invalid timestamp)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 13];
                case 12:
                    error_8 = _a.sent();
                    results.push({
                        name: 'Malformed idempotency key (non-numeric timestamp)',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_8.message,
                    });
                    return [3 /*break*/, 13];
                case 13:
                    _a.trys.push([13, 15, , 16]);
                    publicKey = generateECDHKeyPair().publicKey;
                    idempotencyKey = generateIdempotencyKey().key;
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, idempotencyKey, '', 900)];
                case 14:
                    res = _a.sent();
                    results.push({
                        name: 'Empty X-ClientId header',
                        passed: res.status === 400,
                        expected: '400 (empty client ID)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 16];
                case 15:
                    error_9 = _a.sent();
                    results.push({
                        name: 'Empty X-ClientId header',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_9.message,
                    });
                    return [3 /*break*/, 16];
                case 16: return [2 /*return*/, results];
            }
        });
    });
}
function testPublicKeyValidation() {
    return __awaiter(this, void 0, void 0, function () {
        var results, idempotencyKey, body, res, error_10, invalidBase64, idempotencyKey, res, error_11, wrongLengthKey, idempotencyKey, res, error_12, invalidPoint, i, idempotencyKey, res, error_13, idempotencyKey, res, error_14;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    results = [];
                    console.log('\n=== Public Key Validation Tests ===\n');
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    idempotencyKey = generateIdempotencyKey().key;
                    body = JSON.stringify({ ttlSec: 900 });
                    return [4 /*yield*/, makeRawRequest(ENDPOINT, 'POST', {
                            'Content-Type': 'application/json',
                            'Content-Length': Buffer.byteLength(body).toString(),
                            'X-Idempotency-Key': idempotencyKey,
                            'X-ClientId': 'test-pubkey-1',
                        }, body)];
                case 2:
                    res = _a.sent();
                    results.push({
                        name: 'Missing clientPublicKey field',
                        passed: res.status === 400,
                        expected: '400 (missing field)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 4];
                case 3:
                    error_10 = _a.sent();
                    results.push({
                        name: 'Missing clientPublicKey field',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_10.message,
                    });
                    return [3 /*break*/, 4];
                case 4:
                    _a.trys.push([4, 6, , 7]);
                    invalidBase64 = 'This is not valid base64!!!@@@';
                    idempotencyKey = generateIdempotencyKey().key;
                    return [4 /*yield*/, makeSessionInitRequest(invalidBase64, idempotencyKey, 'test-pubkey-2', 900)];
                case 5:
                    res = _a.sent();
                    results.push({
                        name: 'Invalid base64 encoding in public key',
                        passed: res.status === 400,
                        expected: '400 (invalid base64)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 7];
                case 6:
                    error_11 = _a.sent();
                    results.push({
                        name: 'Invalid base64 encoding in public key',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_11.message,
                    });
                    return [3 /*break*/, 7];
                case 7:
                    _a.trys.push([7, 9, , 10]);
                    wrongLengthKey = Buffer.from('0400', 'hex');
                    idempotencyKey = generateIdempotencyKey().key;
                    return [4 /*yield*/, makeSessionInitRequest(wrongLengthKey.toString('base64'), idempotencyKey, 'test-pubkey-3', 900)];
                case 8:
                    res = _a.sent();
                    results.push({
                        name: 'Wrong length public key (not 65 bytes)',
                        passed: res.status === 400,
                        expected: '400 (invalid key length)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 10];
                case 9:
                    error_12 = _a.sent();
                    results.push({
                        name: 'Wrong length public key (not 65 bytes)',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_12.message,
                    });
                    return [3 /*break*/, 10];
                case 10:
                    _a.trys.push([10, 12, , 13]);
                    invalidPoint = Buffer.alloc(65);
                    invalidPoint[0] = 0x04; // Uncompressed format
                    // Fill with invalid coordinates
                    for (i = 1; i < 65; i++) {
                        invalidPoint[i] = 0xFF;
                    }
                    idempotencyKey = generateIdempotencyKey().key;
                    return [4 /*yield*/, makeSessionInitRequest(invalidPoint.toString('base64'), idempotencyKey, 'test-pubkey-4', 900)];
                case 11:
                    res = _a.sent();
                    results.push({
                        name: 'Invalid curve point (not on P-256 curve)',
                        passed: res.status === 400,
                        expected: '400 (invalid curve point)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 13];
                case 12:
                    error_13 = _a.sent();
                    results.push({
                        name: 'Invalid curve point (not on P-256 curve)',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_13.message,
                    });
                    return [3 /*break*/, 13];
                case 13:
                    _a.trys.push([13, 15, , 16]);
                    idempotencyKey = generateIdempotencyKey().key;
                    return [4 /*yield*/, makeSessionInitRequest('', idempotencyKey, 'test-pubkey-5', 900)];
                case 14:
                    res = _a.sent();
                    results.push({
                        name: 'Empty public key',
                        passed: res.status === 400,
                        expected: '400 (empty key)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 16];
                case 15:
                    error_14 = _a.sent();
                    results.push({
                        name: 'Empty public key',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_14.message,
                    });
                    return [3 /*break*/, 16];
                case 16: return [2 /*return*/, results];
            }
        });
    });
}
function testTTLValidation() {
    return __awaiter(this, void 0, void 0, function () {
        var results, publicKey, idempotencyKey, res, error_15, publicKey, idempotencyKey, res, error_16, publicKey, idempotencyKey, res, error_17, publicKey, idempotencyKey, res, error_18, publicKey, idempotencyKey, res, error_19, publicKey, idempotencyKey, res, error_20, publicKey, idempotencyKey, res, error_21;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    results = [];
                    console.log('\n=== TTL Validation Tests ===\n');
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    publicKey = generateECDHKeyPair().publicKey;
                    idempotencyKey = generateIdempotencyKey().key;
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-1', -100)];
                case 2:
                    res = _a.sent();
                    results.push({
                        name: 'Negative TTL value',
                        passed: res.status === 400,
                        expected: '400 (negative TTL)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 4];
                case 3:
                    error_15 = _a.sent();
                    results.push({
                        name: 'Negative TTL value',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_15.message,
                    });
                    return [3 /*break*/, 4];
                case 4:
                    _a.trys.push([4, 6, , 7]);
                    publicKey = generateECDHKeyPair().publicKey;
                    idempotencyKey = generateIdempotencyKey().key;
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-2', 0)];
                case 5:
                    res = _a.sent();
                    results.push({
                        name: 'Zero TTL value (clamped to minimum)',
                        passed: res.status === 200 && res.body.expiresInSec === 60,
                        expected: '200 with TTL clamped to 60',
                        actual: "".concat(res.status, " with TTL ").concat(res.body.expiresInSec || 'N/A'),
                        error: (res.status !== 200 || res.body.expiresInSec !== 60) ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 7];
                case 6:
                    error_16 = _a.sent();
                    results.push({
                        name: 'Zero TTL value (clamped to minimum)',
                        passed: false,
                        expected: '200',
                        actual: 'Exception thrown',
                        error: error_16.message,
                    });
                    return [3 /*break*/, 7];
                case 7:
                    _a.trys.push([7, 9, , 10]);
                    publicKey = generateECDHKeyPair().publicKey;
                    idempotencyKey = generateIdempotencyKey().key;
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-3', 7200)];
                case 8:
                    res = _a.sent();
                    results.push({
                        name: 'TTL above maximum (clamped to 3600)',
                        passed: res.status === 200 && res.body.expiresInSec === 3600,
                        expected: '200 with TTL clamped to 3600',
                        actual: "".concat(res.status, " with TTL ").concat(res.body.expiresInSec || 'N/A'),
                        error: (res.status !== 200 || res.body.expiresInSec !== 3600) ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 10];
                case 9:
                    error_17 = _a.sent();
                    results.push({
                        name: 'TTL above maximum (clamped to 3600)',
                        passed: false,
                        expected: '200',
                        actual: 'Exception thrown',
                        error: error_17.message,
                    });
                    return [3 /*break*/, 10];
                case 10:
                    _a.trys.push([10, 12, , 13]);
                    publicKey = generateECDHKeyPair().publicKey;
                    idempotencyKey = generateIdempotencyKey().key;
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-4', 30)];
                case 11:
                    res = _a.sent();
                    results.push({
                        name: 'TTL below minimum (clamped to 60)',
                        passed: res.status === 200 && res.body.expiresInSec === 60,
                        expected: '200 with TTL clamped to 60',
                        actual: "".concat(res.status, " with TTL ").concat(res.body.expiresInSec || 'N/A'),
                        error: (res.status !== 200 || res.body.expiresInSec !== 60) ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 13];
                case 12:
                    error_18 = _a.sent();
                    results.push({
                        name: 'TTL below minimum (clamped to 60)',
                        passed: false,
                        expected: '200',
                        actual: 'Exception thrown',
                        error: error_18.message,
                    });
                    return [3 /*break*/, 13];
                case 13:
                    _a.trys.push([13, 15, , 16]);
                    publicKey = generateECDHKeyPair().publicKey;
                    idempotencyKey = generateIdempotencyKey().key;
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-7', 123.45)];
                case 14:
                    res = _a.sent();
                    results.push({
                        name: 'Float/decimal TTL value (non-integer)',
                        passed: res.status === 400,
                        expected: '400 (non-integer TTL)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 16];
                case 15:
                    error_19 = _a.sent();
                    results.push({
                        name: 'Float/decimal TTL value (non-integer)',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_19.message,
                    });
                    return [3 /*break*/, 16];
                case 16:
                    _a.trys.push([16, 18, , 19]);
                    publicKey = generateECDHKeyPair().publicKey;
                    idempotencyKey = generateIdempotencyKey().key;
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-5', 60)];
                case 17:
                    res = _a.sent();
                    results.push({
                        name: 'Valid TTL at minimum boundary (60 sec)',
                        passed: res.status === 200,
                        expected: '200 (valid)',
                        actual: "".concat(res.status),
                        error: res.status !== 200 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 19];
                case 18:
                    error_20 = _a.sent();
                    results.push({
                        name: 'Valid TTL at minimum boundary (60 sec)',
                        passed: false,
                        expected: '200',
                        actual: 'Exception thrown',
                        error: error_20.message,
                    });
                    return [3 /*break*/, 19];
                case 19:
                    _a.trys.push([19, 21, , 22]);
                    publicKey = generateECDHKeyPair().publicKey;
                    idempotencyKey = generateIdempotencyKey().key;
                    return [4 /*yield*/, makeSessionInitRequest(publicKey, idempotencyKey, 'test-ttl-6', 3600)];
                case 20:
                    res = _a.sent();
                    results.push({
                        name: 'Valid TTL at maximum boundary (3600 sec)',
                        passed: res.status === 200,
                        expected: '200 (valid)',
                        actual: "".concat(res.status),
                        error: res.status !== 200 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 22];
                case 21:
                    error_21 = _a.sent();
                    results.push({
                        name: 'Valid TTL at maximum boundary (3600 sec)',
                        passed: false,
                        expected: '200',
                        actual: 'Exception thrown',
                        error: error_21.message,
                    });
                    return [3 /*break*/, 22];
                case 22: return [2 /*return*/, results];
            }
        });
    });
}
function testRequestBodyValidation() {
    return __awaiter(this, void 0, void 0, function () {
        var results, idempotencyKey, res, error_22, idempotencyKey, invalidJson, res, error_23, publicKey, idempotencyKey, body, res, error_24;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    results = [];
                    console.log('\n=== Request Body Validation Tests ===\n');
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    idempotencyKey = generateIdempotencyKey().key;
                    return [4 /*yield*/, makeRawRequest(ENDPOINT, 'POST', {
                            'Content-Type': 'application/json',
                            'Content-Length': '0',
                            'X-Idempotency-Key': idempotencyKey,
                            'X-ClientId': 'test-body-1',
                        }, '')];
                case 2:
                    res = _a.sent();
                    results.push({
                        name: 'Empty request body',
                        passed: res.status === 400,
                        expected: '400 (empty body)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 4];
                case 3:
                    error_22 = _a.sent();
                    results.push({
                        name: 'Empty request body',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_22.message,
                    });
                    return [3 /*break*/, 4];
                case 4:
                    _a.trys.push([4, 6, , 7]);
                    idempotencyKey = generateIdempotencyKey().key;
                    invalidJson = '{invalid json}';
                    return [4 /*yield*/, makeRawRequest(ENDPOINT, 'POST', {
                            'Content-Type': 'application/json',
                            'Content-Length': Buffer.byteLength(invalidJson).toString(),
                            'X-Idempotency-Key': idempotencyKey,
                            'X-ClientId': 'test-body-2',
                        }, invalidJson)];
                case 5:
                    res = _a.sent();
                    results.push({
                        name: 'Invalid JSON in request body',
                        passed: res.status === 400,
                        expected: '400 (invalid JSON)',
                        actual: "".concat(res.status),
                        error: res.status !== 400 ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 7];
                case 6:
                    error_23 = _a.sent();
                    results.push({
                        name: 'Invalid JSON in request body',
                        passed: false,
                        expected: '400',
                        actual: 'Exception thrown',
                        error: error_23.message,
                    });
                    return [3 /*break*/, 7];
                case 7:
                    _a.trys.push([7, 9, , 10]);
                    publicKey = generateECDHKeyPair().publicKey;
                    idempotencyKey = generateIdempotencyKey().key;
                    body = JSON.stringify({ clientPublicKey: publicKey, ttlSec: 900 });
                    return [4 /*yield*/, makeRawRequest(ENDPOINT, 'POST', {
                            'Content-Length': Buffer.byteLength(body).toString(),
                            'X-Idempotency-Key': idempotencyKey,
                            'X-ClientId': 'test-body-3',
                        }, body)];
                case 8:
                    res = _a.sent();
                    results.push({
                        name: 'Missing Content-Type header',
                        passed: res.status === 400 || res.status === 415,
                        expected: '400 or 415 (missing content type)',
                        actual: "".concat(res.status),
                        error: (res.status !== 400 && res.status !== 415) ? JSON.stringify(res.body) : undefined,
                    });
                    return [3 /*break*/, 10];
                case 9:
                    error_24 = _a.sent();
                    results.push({
                        name: 'Missing Content-Type header',
                        passed: false,
                        expected: '400 or 415',
                        actual: 'Exception thrown',
                        error: error_24.message,
                    });
                    return [3 /*break*/, 10];
                case 10: return [2 /*return*/, results];
            }
        });
    });
}
// Main test runner
function runAllTests() {
    return __awaiter(this, void 0, void 0, function () {
        var allResults, _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, passed, failed, total;
        return __generator(this, function (_r) {
            switch (_r.label) {
                case 0:
                    console.log('╔════════════════════════════════════════════════════════════════╗');
                    console.log('║   Negative Test Suite for /v1/session/init Endpoint           ║');
                    console.log('╚════════════════════════════════════════════════════════════════╝');
                    allResults = [];
                    _b = 
                    // Run all test categories
                    (_a = allResults.push).apply;
                    _c = [
                        // Run all test categories
                        allResults];
                    return [4 /*yield*/, testReplayProtection()];
                case 1:
                    // Run all test categories
                    _b.apply(_a, _c.concat([_r.sent()]));
                    _e = (_d = allResults.push).apply;
                    _f = [allResults];
                    return [4 /*yield*/, testHeaderValidation()];
                case 2:
                    _e.apply(_d, _f.concat([_r.sent()]));
                    _h = (_g = allResults.push).apply;
                    _j = [allResults];
                    return [4 /*yield*/, testPublicKeyValidation()];
                case 3:
                    _h.apply(_g, _j.concat([_r.sent()]));
                    _l = (_k = allResults.push).apply;
                    _m = [allResults];
                    return [4 /*yield*/, testTTLValidation()];
                case 4:
                    _l.apply(_k, _m.concat([_r.sent()]));
                    _p = (_o = allResults.push).apply;
                    _q = [allResults];
                    return [4 /*yield*/, testRequestBodyValidation()];
                case 5:
                    _p.apply(_o, _q.concat([_r.sent()]));
                    // Print summary
                    console.log('\n╔════════════════════════════════════════════════════════════════╗');
                    console.log('║                         TEST SUMMARY                           ║');
                    console.log('╚════════════════════════════════════════════════════════════════╝\n');
                    passed = allResults.filter(function (r) { return r.passed; }).length;
                    failed = allResults.filter(function (r) { return !r.passed; }).length;
                    total = allResults.length;
                    console.log("Total Tests:  ".concat(total));
                    console.log("Passed:       ".concat(passed, " \u2713"));
                    console.log("Failed:       ".concat(failed, " \u2717"));
                    console.log("Success Rate: ".concat(((passed / total) * 100).toFixed(1), "%\n"));
                    // Print failed tests details
                    if (failed > 0) {
                        console.log('╔════════════════════════════════════════════════════════════════╗');
                        console.log('║                        FAILED TESTS                            ║');
                        console.log('╚════════════════════════════════════════════════════════════════╝\n');
                        allResults.filter(function (r) { return !r.passed; }).forEach(function (result, index) {
                            console.log("".concat(index + 1, ". ").concat(result.name));
                            console.log("   Expected: ".concat(result.expected));
                            console.log("   Actual:   ".concat(result.actual));
                            if (result.error) {
                                console.log("   Error:    ".concat(result.error));
                            }
                            console.log('');
                        });
                    }
                    // Exit with appropriate code
                    process.exit(failed > 0 ? 1 : 0);
                    return [2 /*return*/];
            }
        });
    });
}
// Run tests
runAllTests().catch(function (error) {
    console.error('Test suite failed with error:', error);
    process.exit(1);
});
