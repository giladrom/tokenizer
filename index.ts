import fastify from "fastify";
import * as crypto from "crypto";

const server = fastify();

interface IQuerystring {
  t: string;
}

interface IBodystring {
  secret: string;
}

interface IToken {
  token: string;
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

server.post(
  "/tokens",
  {
    preValidation: (request, reply, done) => {
      const b: IBodystring = request.body as any;
      done(b.secret !== "token" ? new Error("Error") : undefined);
    },
  },
  async (request, reply) => {
    return `output token`;
  }
);

server.put(
  "/tokens",
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

server.listen({ port: 8080 }, (err, address) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.log(`Server listening at ${address}`);
});
