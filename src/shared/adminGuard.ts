import { Elysia } from "elysia";
import { AppError } from "./errors.ts";
import { equalSecret } from "./security.ts";
import { verifyJwtToken } from "./jwt.ts";

/**
 * Options for configuring the admin authentication guard.
 */
export interface AdminGuardOptions {
	adminKey: string;
	oidcIssuer?: string;
	oidcAudience?: string;
}

/**
 * Scoped admin authentication guard middleware.
 *
 * Supports dual authentication:
 * 1. Bearer JWT tokens verified against the OIDC issuer JWKS.
 * 2. Static `X-Admin-Key` header verified against `KEYZORI_ADMIN_KEY`.
 *
 * @param options The admin guard configuration options or static secret string.
 */
export function adminGuard(options: string | AdminGuardOptions) {
	const config: AdminGuardOptions =
		typeof options === "string" ? { adminKey: options } : options;

	return new Elysia({
		name: "keyzori-admin-guard",
		seed: config.adminKey,
		detail: {
			security: [{ adminKey: [] }, { bearerAuth: [] }],
		},
	}).onBeforeHandle({ as: "scoped" }, async ({ request }) => {
		const authHeader = request.headers.get("authorization");
		const xAdminKey = request.headers.get("x-admin-key");

		if (authHeader?.toLowerCase().startsWith("bearer ")) {
			if (!config.oidcIssuer) {
				throw new AppError(
					"UNAUTHORIZED",
					"Bearer authentication is not configured on this server (KEYZORI_OIDC_ISSUER missing).",
					401,
				);
			}

			const token = authHeader.slice(7).trim();
			await verifyJwtToken(token, config.oidcIssuer, config.oidcAudience);
			return;
		}

		if (xAdminKey && equalSecret(xAdminKey, config.adminKey)) {
			return;
		}

		throw new AppError(
			"UNAUTHORIZED",
			"A valid X-Admin-Key or Authorization Bearer token is required.",
			401,
		);
	});
}
export type AdminGuard = ReturnType<typeof adminGuard>;
