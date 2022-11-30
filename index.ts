import fastify from "fastify";
import helmet from "@fastify/helmet";

import * as crypto from "crypto";
import { Database } from "sqlite3";
import { v4 as uuidv4 } from "uuid";

const server = fastify();
server.register(helmet);

const TOKEN = "dp.token.12345";
const key = crypto.randomBytes(32).toString("hex");

const db = new Database(":memory:");

interface IQuerystring {
  t: string;
}

interface IBodystring {
  secret: string;
}

interface IToken {
  token: string;
}

// Use SQLite to guarantee asynchronous operation w/o race conditions

function initDb() {
  return new Promise((resolve, reject) => {
    db.exec(
      `CREATE TABLE tokens (
      token VARCHAR(256) NOT NULL,
      secret VARCHAR(256) NOT NULL
      )`,
      (err) => {
        if (err) {
          reject(err);
        } else {
          resolve(true);
        }
      }
    );
  });
}

function generateToken(secret: string) {
  return new Promise((resolve, reject) => {
    const newToken = uuidv4();
    const encryptedSecret = encrypt(secret, key);

    db.exec(
      `INSERT INTO tokens VALUES (
      '${newToken}', '${encryptedSecret}'
    )`,
      (err) => {
        if (err) {
          reject(err);
        } else {
          resolve(newToken);
        }
      }
    );
  });
}

// AES-256-GCM encryption using a pre-computed key and random IV

function encrypt(
  plaintext: string,
  key:
    | WithImplicitCoercion<string>
    | { [Symbol.toPrimitive](hint: "string"): string }
) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    Buffer.from(key, "hex"),
    iv
  );
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([iv, tag, encrypted]).toString("hex");
}

function decrypt(
  ciphertext:
    | WithImplicitCoercion<string>
    | { [Symbol.toPrimitive](hint: "string"): string },
  key:
    | WithImplicitCoercion<string>
    | { [Symbol.toPrimitive](hint: "string"): string }
) {
  const data = Buffer.from(ciphertext, "hex");
  const iv = data.slice(0, 16);
  const tag = data.slice(16, 32);
  const text = data.slice(32);
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    Buffer.from(key, "hex"),
    iv
  );
  decipher.setAuthTag(tag);

  return (
    decipher.update(text, "binary" as any, "utf8") + decipher.final("utf8")
  );
}

// REST API

// Read
// OP: GET /tokens?t=<TOKEN 1>,<TOKEN 2>
// Return: { “<TOKEN 1>”: “<SECRET 1>”, “<TOKEN 2>”: “<SECRET 2>” }

server.get<{
  Querystring: IQuerystring;
}>(
  "/tokens",
  {
    preValidation: (request, reply, done) => {
      const { t } = request.query;
      done(t !== "token" ? new Error("Error") : undefined);
    },
  },
  async (request, reply) => {
    const { t } = request.query;
    // do something with request data

    return `logged in!`;
  }
);

// Write
// OP: PUT /tokens
// Body: { “secret”: “<SECRET>” }
// Return: { “token”: “<TOKEN>” }

server.post(
  "/tokens",
  {
    preValidation: (request, reply, done) => {
      const b: IBodystring = request.body as any;
      done(b.secret !== "token" ? new Error("Error") : undefined);
    },
  },
  async (request, reply) => {
    const b: IBodystring = request.body as any;

    const token = await generateToken(b.secret);

    console.log(token);
    reply.send(token);
  }
);

// Update
// OP: PUT /tokens/<TOKEN>
// Body: { “secret”: “<SECRET>” }
// Return: None (status 204)

server.put(
  "/tokens/:token",
  {
    preValidation: (request, reply, done) => {
      const b: IBodystring = request.body as any;
      done(b.secret !== "token" ? new Error("Error") : undefined);
    },
  },
  async (request, reply) => {
    reply.code(204);
  }
);

// Delete
// OP: DELETE /tokens/<TOKEN>
// Return: None (status 204)

server.delete(
  "/tokens/:token",
  {
    preValidation: (request, reply, done) => {
      const b = request.params;
      done(b !== "token" ? new Error("Error") : undefined);
    },
  },
  async (request, reply) => {
    reply.code(204);
  }
);

initDb();
server.listen({ port: 8080 }, (err, address) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.log(`Server listening at ${address}`);
});
