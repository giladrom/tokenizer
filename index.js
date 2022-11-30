"use strict";
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
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fastify_1 = __importDefault(require("fastify"));
const helmet_1 = __importDefault(require("@fastify/helmet"));
const crypto = __importStar(require("crypto"));
const sqlite3_1 = require("sqlite3");
const uuid_1 = require("uuid");
const server = (0, fastify_1.default)();
server.register(helmet_1.default);
const TOKEN = "dp.token.12345";
const key = crypto.randomBytes(32).toString("hex");
const db = new sqlite3_1.Database(":memory:");
// Use SQLite to guarantee asynchronous operation w/o race conditions
function initDb() {
    return new Promise((resolve, reject) => {
        db.exec(`CREATE TABLE tokens (
      token VARCHAR(256) NOT NULL,
      secret VARCHAR(256) NOT NULL
      )`, (err) => {
            if (err) {
                reject(err);
            }
            else {
                resolve(true);
            }
        });
    });
}
function generateToken(secret) {
    return new Promise((resolve, reject) => {
        const newToken = (0, uuid_1.v4)();
        const encryptedSecret = encrypt(secret, key);
        db.exec(`INSERT INTO tokens VALUES (
      '${newToken}', '${encryptedSecret}'
    )`, (err) => {
            if (err) {
                reject(err);
            }
            else {
                resolve(newToken);
            }
        });
    });
}
// AES-256-GCM encryption using a pre-computed key and random IV
function encrypt(plaintext, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(key, "hex"), iv);
    const encrypted = Buffer.concat([
        cipher.update(plaintext, "utf8"),
        cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, encrypted]).toString("hex");
}
function decrypt(ciphertext, key) {
    const data = Buffer.from(ciphertext, "hex");
    const iv = data.slice(0, 16);
    const tag = data.slice(16, 32);
    const text = data.slice(32);
    const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(key, "hex"), iv);
    decipher.setAuthTag(tag);
    return (decipher.update(text, "binary", "utf8") + decipher.final("utf8"));
}
// REST API
// Read
// OP: GET /tokens?t=<TOKEN 1>,<TOKEN 2>
// Return: { “<TOKEN 1>”: “<SECRET 1>”, “<TOKEN 2>”: “<SECRET 2>” }
server.get("/tokens", {
    preValidation: (request, reply, done) => {
        const { t } = request.query;
        done(t !== "token" ? new Error("Error") : undefined);
    },
}, async (request, reply) => {
    const { t } = request.query;
    // do something with request data
    return `logged in!`;
});
// Write
// OP: PUT /tokens
// Body: { “secret”: “<SECRET>” }
// Return: { “token”: “<TOKEN>” }
server.post("/tokens", {
    preValidation: (request, reply, done) => {
        const b = request.body;
        done(b.secret !== "token" ? new Error("Error") : undefined);
    },
}, async (request, reply) => {
    const b = request.body;
    const token = await generateToken(b.secret);
    console.log(token);
    reply.send(token);
});
// Update
// OP: PUT /tokens/<TOKEN>
// Body: { “secret”: “<SECRET>” }
// Return: None (status 204)
server.put("/tokens/:token", {
    preValidation: (request, reply, done) => {
        const b = request.body;
        done(b.secret !== "token" ? new Error("Error") : undefined);
    },
}, async (request, reply) => {
    reply.code(204);
});
// Delete
// OP: DELETE /tokens/<TOKEN>
// Return: None (status 204)
server.delete("/tokens/:token", {
    preValidation: (request, reply, done) => {
        const b = request.params;
        done(b !== "token" ? new Error("Error") : undefined);
    },
}, async (request, reply) => {
    reply.code(204);
});
initDb();
server.listen({ port: 8080 }, (err, address) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    console.log(`Server listening at ${address}`);
});
