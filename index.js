"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fastify_1 = __importDefault(require("fastify"));
const server = (0, fastify_1.default)();
server.get('/tokens', {
    preValidation: (request, reply, done) => {
        const { t } = request.query;
        done(t !== 'token' ? new Error('Error') : undefined);
    }
}, async (request, reply) => {
    const { t } = request.query;
    // do something with request data
    return `logged in!`;
});
server.post('/tokens', {
    preValidation: (request, reply, done) => {
        const b = request.body;
        done(b.secret !== 'token' ? new Error('Error') : undefined);
    }
}, async (request, reply) => {
    return `output token`;
});
server.listen({ port: 8080 }, (err, address) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    console.log(`Server listening at ${address}`);
});
