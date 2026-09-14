import { expect, test } from "bun:test";
import { Elysia } from "elysia";
import { adminGuard } from "../../src/shared/adminGuard.ts";

function base64UrlEncode(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64url");
}

async function createMockJwt(
	privateKey: CryptoKey,
	kid: string,
	payload: Record<string, unknown>,
) {
	const header = { alg: "ES256", typ: "at+jwt", kid };
	const enc = new TextEncoder();
	const encHeader = base64UrlEncode(enc.encode(JSON.stringify(header)));
	const encPayload = base64UrlEncode(enc.encode(JSON.stringify(payload)));
	const data = enc.encode(`${encHeader}.${encPayload}`);

	const sig = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		privateKey,
		data,
	);
	const encSig = base64UrlEncode(new Uint8Array(sig));
	return `${encHeader}.${encPayload}.${encSig}`;
}

test("adminGuard accepts valid X-Admin-Key", async () => {
	const guard = adminGuard("super-secure-admin-secret-at-least-32-chars");
	const app = new Elysia().use(guard).get("/admin/test", () => ({ ok: true }));

	const res = await app.handle(
		new Request("http://localhost/admin/test", {
			headers: { "x-admin-key": "super-secure-admin-secret-at-least-32-chars" },
		}),
	);

	expect(res.status).toBe(200);
	expect(await res.json()).toEqual({ ok: true });
});

test("adminGuard rejects missing or incorrect X-Admin-Key", async () => {
	const guard = adminGuard("super-secure-admin-secret-at-least-32-chars");
	const app = new Elysia().use(guard).get("/admin/test", () => ({ ok: true }));

	const res1 = await app.handle(new Request("http://localhost/admin/test"));
	expect(res1.status).toBe(401);

	const res2 = await app.handle(
		new Request("http://localhost/admin/test", {
			headers: { "x-admin-key": "wrong-key" },
		}),
	);
	expect(res2.status).toBe(401);
});

test("adminGuard validates ES256 Bearer JWT against JWKS", async () => {
	const keyPair = await crypto.subtle.generateKey(
		{ name: "ECDSA", namedCurve: "P-256" },
		true,
		["sign", "verify"],
	);
	const publicJwk = (await crypto.subtle.exportKey(
		"jwk",
		keyPair.publicKey,
	)) as JsonWebKey & { kid?: string };
	publicJwk.kid = "test-key-1";

	const mockJwksServer = Bun.serve({
		port: 0,
		fetch(req) {
			if (new URL(req.url).pathname === "/.well-known/jwks.json") {
				return Response.json({ keys: [publicJwk] });
			}
			return new Response("Not Found", { status: 404 });
		},
	});

	const issuer = `http://localhost:${mockJwksServer.port}`;

	try {
		const guard = adminGuard({
			adminKey: "super-secure-admin-secret-at-least-32-chars",
			oidcIssuer: issuer,
			oidcAudience: "keyzori",
		});

		const app = new Elysia()
			.use(guard)
			.get("/admin/test", () => ({ ok: true }));

		const validToken = await createMockJwt(keyPair.privateKey, "test-key-1", {
			iss: issuer,
			sub: "service-client-1",
			aud: "keyzori",
			scope: "licenses:create",
			exp: Math.floor(Date.now() / 1000) + 3600,
		});

		const resValid = await app.handle(
			new Request("http://localhost/admin/test", {
				headers: { authorization: `Bearer ${validToken}` },
			}),
		);
		expect(resValid.status).toBe(200);

		const expiredToken = await createMockJwt(keyPair.privateKey, "test-key-1", {
			iss: issuer,
			sub: "service-client-1",
			aud: "keyzori",
			scope: "licenses:create",
			exp: Math.floor(Date.now() / 1000) - 60,
		});

		const resExpired = await app.handle(
			new Request("http://localhost/admin/test", {
				headers: { authorization: `Bearer ${expiredToken}` },
			}),
		);
		expect(resExpired.status).toBe(401);

		const wrongAudToken = await createMockJwt(
			keyPair.privateKey,
			"test-key-1",
			{
				iss: issuer,
				sub: "service-client-1",
				aud: "other-service",
				exp: Math.floor(Date.now() / 1000) + 3600,
			},
		);

		const resWrongAud = await app.handle(
			new Request("http://localhost/admin/test", {
				headers: { authorization: `Bearer ${wrongAudToken}` },
			}),
		);
		expect(resWrongAud.status).toBe(401);
	} finally {
		mockJwksServer.stop();
	}
});

test("adminGuard validates RS256 Bearer JWT and dynamic OIDC discovery", async () => {
	const rsaKeyPair = await crypto.subtle.generateKey(
		{
			name: "RSASSA-PKCS1-v1_5",
			modulusLength: 2048,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: "SHA-256",
		},
		true,
		["sign", "verify"],
	);

	const publicJwk = (await crypto.subtle.exportKey(
		"jwk",
		rsaKeyPair.publicKey,
	)) as JsonWebKey & { kid?: string; alg?: string };
	publicJwk.kid = "rsa-key-1";
	publicJwk.alg = "RS256";

	const mockOidcServer: ReturnType<typeof Bun.serve> = Bun.serve({
		port: 0,
		fetch(req): Response {
			const url = new URL(req.url);
			if (url.pathname === "/.well-known/openid-configuration") {
				return Response.json({
					jwks_uri: `http://localhost:${mockOidcServer.port}/custom/keys`,
				});
			}
			if (url.pathname === "/custom/keys") {
				return Response.json({ keys: [publicJwk] });
			}
			return new Response("Not Found", { status: 404 });
		},
	});

	const issuer = `http://localhost:${mockOidcServer.port}`;

	try {
		const guard = adminGuard({
			adminKey: "super-secure-admin-secret-at-least-32-chars",
			oidcIssuer: issuer,
			oidcAudience: "keyzori",
		});

		const app = new Elysia()
			.use(guard)
			.get("/admin/test", () => ({ ok: true }));

		const header = { alg: "RS256", typ: "at+jwt", kid: "rsa-key-1" };
		const payload = {
			iss: issuer,
			sub: "auth0|client_123",
			aud: "keyzori",
			exp: Math.floor(Date.now() / 1000) + 3600,
		};
		const enc = new TextEncoder();
		const encHeader = base64UrlEncode(enc.encode(JSON.stringify(header)));
		const encPayload = base64UrlEncode(enc.encode(JSON.stringify(payload)));
		const data = enc.encode(`${encHeader}.${encPayload}`);
		const sig = await crypto.subtle.sign(
			"RSASSA-PKCS1-v1_5",
			rsaKeyPair.privateKey,
			data,
		);
		const encSig = base64UrlEncode(new Uint8Array(sig));
		const rsaToken = `${encHeader}.${encPayload}.${encSig}`;

		const res = await app.handle(
			new Request("http://localhost/admin/test", {
				headers: { authorization: `Bearer ${rsaToken}` },
			}),
		);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true });
	} finally {
		mockOidcServer.stop();
	}
});
