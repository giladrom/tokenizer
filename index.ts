import fastify from "fastify";
import helmet from "@fastify/helmet";
import fs from "fs";

import * as crypto from "crypto";
import { Database } from "sqlite3";
import { v4 as uuidv4 } from "uuid";
import bearerAuthPlugin from "@fastify/bearer-auth";
import rateLimitPlugin from "@fastify/rate-limit";

// Using self signed certificate
// openssl req -nodes -new -x509 -keyout server.key -out server.cert
// Make sure to test with curl -k

//* This can be modified to restrict requests to a our internal network/subnet
const HOSTS = "192.168.0.0/24";

//* In production this will use a Doppler variable/secure keystore
const keys = new Set(["32C8EF54-F692-46B4-A24A-AE139A73D2DA"]);

const server = fastify({
  logger: true,
  http2: true,
  https: {
    allowHTTP1: true,
    key: fs.readFileSync("./https/server.key"),
    cert: fs.readFileSync("./https/server.cert"),
  },
  bodyLimit: 1024,
  trustProxy: HOSTS,
});

// Use helmet for better HTTP header security

server.register(helmet, { global: true });
server.register(bearerAuthPlugin, { keys });
server.register(rateLimitPlugin, {
  global: true,
  max: 10,
  timeWindow: "1 minute",
});

// Rate limit 404 response to prevent rapid guessing of valid routes

server.setNotFoundHandler(
  {
    preValidation: (request, reply, done) => {
      server.rateLimit();
      done(undefined);
    },
  },
  function (request, reply) {
    reply.code(404).send({ resposne: "Error" });
  }
);

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
      id integer PRIMARY KEY AUTOINCREMENT,
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
    const newToken = "dp.token." + uuidv4().replace(/\-/gi, "");
    const encryptedSecret = encrypt(secret, key);

    db.run(
      `INSERT INTO tokens (token, secret) VALUES (?, ?);`,
      [newToken, encryptedSecret],
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

function retrieveSecret(token: any) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM tokens WHERE token = ?;`, [token], (_, res) => {
      resolve(res);
    });
  });
}

function updateSecret(token: any, secret: string) {
  return new Promise((resolve, reject) => {
    const encryptedSecret = encrypt(secret, key);

    db.run(
      `UPDATE tokens SET secret = '${encryptedSecret}' WHERE token = ?;`,
      [token],
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

function deleteToken(token: any) {
  return new Promise((resolve, reject) => {
    db.run(`DELETE FROM tokens WHERE token = ?;`, [token], (err) => {
      if (err) {
        reject(err);
      } else {
        resolve(true);
      }
    });
  });
}

//! DEBUG
function getDB() {
  return new Promise((resolve, reject) => {
    db.all(`SELECT * FROM tokens;`, (_, res) => {
      resolve(res);
    });
  });
}
//!

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
//* Status: DONE

server.get<{
  Querystring: IQuerystring;
}>(
  "/tokens",
  {
    preValidation: (request, reply, done) => {
      // Validate that all tokens match our predefined pattern
      // Token has to be between 1-256 characters long

      try {
        const tokens = request.query;
        const array = tokens.t.match(/dp.token.\w{1,256}/gi);

        //* /tokens?t=dp.token.1234,dp.token.5678 -> PASS
        //* /tokens?t=dp.token.1234,dp.token.     -> FAIL
        //* /tokens?t=                            -> FAIL

        done(
          !(Array.isArray(array) && tokens.t.split(",").length === array.length)
            ? new Error("Error")
            : undefined
        );
      } catch (e) {
        done(new Error("Error"));
      }
    },
  },

  async (request, reply) => {
    const query = request.query as IQuerystring;
    const tokens = query.t.match(/dp.token.\w{1,256}/gi);

    if (tokens) {
      try {
        const ret = tokens.map(async (token) => {
          try {
            const secret = (await retrieveSecret(token)) as any;
            const decryptedSecret = decrypt(secret.secret, key);

            const values = {
              token: token,
              secret: decryptedSecret,
            };

            return values;
          } catch {
            return;
          }
        });

        const secrets = await Promise.all(ret);
        return secrets;
      } catch (e) {
        return;
      }
    } else {
      return;
    }
  }
);

// Write
// OP: PUT /tokens
// Body: { “secret”: “<SECRET>” }
// Return: { “token”: “<TOKEN>” }
//* Status: DONE

server.post(
  "/tokens",
  {
    preValidation: (request, reply, done) => {
      const b: IBodystring = request.body as any;

      // Validate the secret matches a predefined pattern

      try {
        done(!b.secret.match(/\b\w{1,256}\b/) ? new Error("Error") : undefined);
      } catch (e) {
        done(new Error("Error"));
      }
    },
  },
  async (request, reply) => {
    const b: IBodystring = request.body as any;

    const token = (await generateToken(b.secret)) as IToken;

    reply.send({
      token: token,
    });
  }
);

// Update
// OP: PUT /tokens/<TOKEN>
// Body: { “secret”: “<SECRET>” }
// Return: None (status 204)
//* Status: DONE

server.put(
  "/tokens/:token",
  {
    preValidation: (request, reply, done) => {
      const b: IBodystring = request.body as any;
      const params: any = request.params;

      try {
        if (!params.token.match(/dp.token.\w{1,256}/)) {
          done(new Error("Error"));
        }

        done(!b.secret.match(/\b\w{1,256}\b/) ? new Error("Error") : undefined);
      } catch (e) {
        done(new Error("Error"));
      }
    },
  },
  async (request, reply) => {
    const token = (request.params as any).token;
    const secret = (request.body as IBodystring).secret;

    await updateSecret(token, secret);
    reply.code(204);
  }
);

// Delete
// OP: DELETE /tokens/<TOKEN>
// Return: None (status 204)
//* Status: DONE

server.delete(
  "/tokens/:token",
  {
    preValidation: (request, reply, done) => {
      const params: any = request.params;

      try {
        if (!params.token.match(/dp.token.\w{1,256}/)) {
          done(new Error("Error"));
        } else {
          done(undefined);
        }
      } catch (e) {
        done(new Error("Error"));
      }
    },
  },
  async (request, reply) => {
    const token = (request.params as any).token;

    await deleteToken(token);
    reply.code(204);
  }
);

//! DEBUG
server.all("/db", async (request, reply) => {
  return await getDB();
});
//! DEBUG

initDb();
server.listen({ port: 8080 }, (err, address) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.log(`Server listening at ${address}`);
});
