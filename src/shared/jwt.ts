import { AppError } from "./errors.ts";

/**
 * Decoded OpenID Connect / OAuth 2.0 access token payload.
 */
export interface JwtPayload {
	iss?: string;
	sub?: string;
	aud?: string | string[];
	client_id?: string;
	scope?: string;
	exp?: number;
	nbf?: number;
	iat?: number;
	jti?: string;
	[key: string]: unknown;
}

interface ParsedKey {
	cryptoKey: CryptoKey;
	verifyAlgorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
}

interface JwksCache {
	keys: Map<string, ParsedKey>;
	fetchedAt: number;
}

const jwksCacheMap = new Map<string, JwksCache>();
const issuerJwksUriMap = new Map<string, string>();
const CACHE_TTL_MS = 1000 * 60 * 60;

function base64UrlDecode(str: string): string {
	let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
	while (base64.length % 4) {
		base64 += "=";
	}
	return atob(base64);
}

/**
 * Resolves the JWKS URI for an OIDC issuer via `/.well-known/openid-configuration`
 * with a fallback to standard `/.well-known/jwks.json`.
 *
 * @param issuer The base URL of the Identity Provider.
 * @returns The resolved JWKS URI endpoint.
 */
export async function resolveJwksUri(issuer: string): Promise<string> {
	const normalizedIssuer = issuer.replace(/\/+$/, "");
	const cached = issuerJwksUriMap.get(normalizedIssuer);
	if (cached) return cached;

	try {
		const discoveryRes = await fetch(
			`${normalizedIssuer}/.well-known/openid-configuration`,
		);
		if (discoveryRes.ok) {
			const config = (await discoveryRes.json()) as { jwks_uri?: string };
			if (config.jwks_uri && typeof config.jwks_uri === "string") {
				issuerJwksUriMap.set(normalizedIssuer, config.jwks_uri);
				return config.jwks_uri;
			}
		}
	} catch {
		// Fallback if discovery endpoint is unreachable
	}

	const fallbackUri = `${normalizedIssuer}/.well-known/jwks.json`;
	issuerJwksUriMap.set(normalizedIssuer, fallbackUri);
	return fallbackUri;
}

/**
 * Fetches and imports public keys from a JWKS endpoint into WebCrypto `CryptoKey` instances.
 * Supports ECDSA (ES256, ES384, ES512), RSA (RS256, RS384, RS512), and Ed25519.
 *
 * @param jwksUri The remote JWKS endpoint URI.
 * @returns A Map of key ID (`kid`) to parsed WebCrypto keys.
 */
export async function fetchJwksKeys(
	jwksUri: string,
): Promise<Map<string, ParsedKey>> {
	const cached = jwksCacheMap.get(jwksUri);
	const now = Date.now();
	if (cached && now - cached.fetchedAt < CACHE_TTL_MS) {
		return cached.keys;
	}

	const res = await fetch(jwksUri);
	if (!res.ok) {
		throw new AppError(
			"UNAVAILABLE",
			`Failed to fetch OIDC JWKS from ${jwksUri}`,
			503,
		);
	}

	const body = (await res.json()) as {
		keys: Array<
			JsonWebKey & {
				kid?: string;
				kty?: string;
				crv?: string;
				alg?: string;
			}
		>;
	};
	const keyMap = new Map<string, ParsedKey>();

	for (const jwk of body.keys) {
		if (!jwk.kid) continue;
		try {
			if (jwk.kty === "EC") {
				const curve = jwk.crv || "P-256";
				const hash =
					curve === "P-384"
						? "SHA-384"
						: curve === "P-521"
							? "SHA-512"
							: "SHA-256";

				const cryptoKey = await crypto.subtle.importKey(
					"jwk",
					jwk,
					{ name: "ECDSA", namedCurve: curve },
					false,
					["verify"],
				);

				keyMap.set(jwk.kid, {
					cryptoKey,
					verifyAlgorithm: { name: "ECDSA", hash: { name: hash } },
				});
			} else if (jwk.kty === "RSA") {
				const alg = jwk.alg || "RS256";
				const hash =
					alg === "RS384" ? "SHA-384" : alg === "RS512" ? "SHA-512" : "SHA-256";

				const cryptoKey = await crypto.subtle.importKey(
					"jwk",
					jwk,
					{ name: "RSASSA-PKCS1-v1_5", hash: { name: hash } },
					false,
					["verify"],
				);

				keyMap.set(jwk.kid, {
					cryptoKey,
					verifyAlgorithm: { name: "RSASSA-PKCS1-v1_5" },
				});
			} else if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
				const cryptoKey = await crypto.subtle.importKey(
					"jwk",
					jwk,
					{ name: "Ed25519" },
					false,
					["verify"],
				);

				keyMap.set(jwk.kid, {
					cryptoKey,
					verifyAlgorithm: { name: "Ed25519" },
				});
			}
		} catch {
			// Skip unsupported key formats
		}
	}

	jwksCacheMap.set(jwksUri, { keys: keyMap, fetchedAt: now });
	return keyMap;
}

/**
 * Validates and decodes a Bearer JWT access token against an OIDC issuer's JWKS.
 * Performs cryptographic signature verification, expiration check, not-before check,
 * issuer matching, and audience matching.
 *
 * @param token Raw encoded JWT string.
 * @param expectedIssuer Expected issuer URL.
 * @param expectedAudience Expected audience identifier.
 * @returns The validated token claims payload.
 */
export async function verifyJwtToken(
	token: string,
	expectedIssuer: string,
	expectedAudience?: string,
): Promise<JwtPayload> {
	const parts = token.split(".");
	if (parts.length !== 3) {
		throw new AppError("UNAUTHORIZED", "Malformed JWT access token.", 401);
	}

	const [encodedHeader, encodedPayload, encodedSignature] = parts;
	if (!encodedHeader || !encodedPayload || !encodedSignature) {
		throw new AppError("UNAUTHORIZED", "Malformed JWT access token.", 401);
	}

	let header: { alg?: string; kid?: string; typ?: string };
	let payload: JwtPayload;

	try {
		header = JSON.parse(base64UrlDecode(encodedHeader));
		payload = JSON.parse(base64UrlDecode(encodedPayload));
	} catch {
		throw new AppError("UNAUTHORIZED", "Invalid JWT encoding or JSON.", 401);
	}

	if (!header.kid) {
		throw new AppError("UNAUTHORIZED", "JWT header is missing 'kid'.", 401);
	}

	const normalizedIssuer = expectedIssuer.replace(/\/+$/, "");
	const jwksUri = await resolveJwksUri(normalizedIssuer);

	let keys = await fetchJwksKeys(jwksUri);
	let parsedKey = keys.get(header.kid);

	if (!parsedKey) {
		jwksCacheMap.delete(jwksUri);
		keys = await fetchJwksKeys(jwksUri);
		parsedKey = keys.get(header.kid);
	}

	if (!parsedKey) {
		throw new AppError(
			"UNAUTHORIZED",
			`Unknown signing key ID '${header.kid}'.`,
			401,
		);
	}

	const sigBin = base64UrlDecode(encodedSignature);
	const sigBytes = new Uint8Array(sigBin.length);
	for (let i = 0; i < sigBin.length; i++) {
		sigBytes[i] = sigBin.charCodeAt(i);
	}

	const data = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`);
	const isValid = await crypto.subtle.verify(
		parsedKey.verifyAlgorithm,
		parsedKey.cryptoKey,
		sigBytes,
		data,
	);

	if (!isValid) {
		throw new AppError(
			"UNAUTHORIZED",
			"JWT signature verification failed.",
			401,
		);
	}

	const nowSec = Math.floor(Date.now() / 1000);

	if (payload.exp && payload.exp < nowSec) {
		throw new AppError("UNAUTHORIZED", "JWT access token has expired.", 401);
	}

	if (payload.nbf && payload.nbf > nowSec) {
		throw new AppError(
			"UNAUTHORIZED",
			"JWT access token is not yet valid.",
			401,
		);
	}

	if (payload.iss && payload.iss.replace(/\/+$/, "") !== normalizedIssuer) {
		throw new AppError(
			"UNAUTHORIZED",
			`JWT issuer '${payload.iss}' does not match expected '${expectedIssuer}'.`,
			401,
		);
	}

	if (expectedAudience) {
		const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
		if (!aud.includes(expectedAudience)) {
			throw new AppError(
				"UNAUTHORIZED",
				`JWT audience does not include '${expectedAudience}'.`,
				401,
			);
		}
	}

	return payload;
}
