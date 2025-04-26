import { server } from "@passwordless-id/webauthn";
import { AuthenticationEncoded, RegistrationEncoded, RegistrationParsed } from "@passwordless-id/webauthn/src/types";

interface Env {
	Storage: KVNamespace;
}

interface UserStorage {
	challenge: string;
	credentials: RegistrationParsed[];
}

type ChallengeReq = { username: string };
type RegisterReq = { username: string; registration: RegistrationEncoded };
type LoginReq = { username: string; authentication: AuthenticationEncoded };

/* ---------- 共用 ─────────────────────── */

const cors = {
	"Access-Control-Allow-Origin": "*", // ← 若要限制網域換成實際網址
	"Access-Control-Allow-Methods": "GET,POST,OPTIONS",
	"Access-Control-Allow-Headers": "Content-Type",
	"Access-Control-Max-Age": "86400",
};

function jsonResponse({ data = {}, status = 200 }: { data?: unknown; status?: number }): Response {
	return new Response(JSON.stringify(data), {
		status,
		headers: {
			...cors,
			"Cache-Control": "no-cache, no-store, must-revalidate",
			"Content-Type": "application/json",
		},
	});
}

/* ---------- Worker 入口 ───────────────── */

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const { pathname, host } = new URL(request.url);

		/* 1. 處理預檢 (OPTIONS) */
		if (request.method === "OPTIONS") {
			return new Response(null, { status: 204, headers: cors });
		}

		/* 2. 路由 */
		switch (pathname) {
			/* ────────── 註冊：challenge ────────── */
			case "/register/challenge": {
				const { username } = (await request.json()) as ChallengeReq;
				if (!username) return jsonResponse({ status: 400 });

				const challenge = crypto.randomUUID();
				const storage: UserStorage = (await env.Storage.get(username, { type: "json" })) ?? {
					challenge: "",
					credentials: [],
				};

				await env.Storage.put(username, JSON.stringify({ ...storage, challenge }));

				return new Response(challenge, { status: 200, headers: cors });
			}

			/* ────────── 註冊：verify ────────── */
			case "/register/verify": {
				const { username, registration } = (await request.json()) as RegisterReq;
				if (!username || !registration) return jsonResponse({ status: 400 });

				const storage: UserStorage | null = await env.Storage.get(username, {
					type: "json",
				});
				if (!storage?.challenge) return jsonResponse({ status: 410 }); // challenge 過期

				try {
					const parsed = await server.verifyRegistration(registration, {
						challenge: storage.challenge,
						origin: host,
					});

					await env.Storage.put(
						username, // ← 與 get 時保持一致
						JSON.stringify({
							...storage,
							credentials: [...storage.credentials, parsed],
						})
					);
					return jsonResponse({ status: 200 });
				} catch (e) {
					return jsonResponse({ status: 400, data: e });
				}
			}

			/* ────────── 登入：challenge ────────── */
			case "/login/challenge": {
				const { username } = (await request.json()) as ChallengeReq;
				if (!username) return jsonResponse({ status: 400 });

				const storage: UserStorage | null = await env.Storage.get(username, {
					type: "json",
				});
				if (!storage?.credentials?.length) return jsonResponse({ status: 404 });

				const challenge = crypto.randomUUID();
				await env.Storage.put(username, JSON.stringify({ ...storage, challenge }));

				return jsonResponse({
					data: {
						challenge,
						credentialIds: storage.credentials.map((c) => c.credential.id),
					},
				});
			}

			/* ────────── 登入：verify ────────── */
			case "/login/verify": {
				const { username, authentication } = (await request.json()) as LoginReq;
				if (!username || !authentication) return jsonResponse({ status: 400 });

				const storage: UserStorage | null = await env.Storage.get(username, {
					type: "json",
				});
				if (!storage?.challenge) return jsonResponse({ status: 410 });

				const cred = storage.credentials.find((c) => c.credential.id === authentication.credentialId);
				if (!cred) return jsonResponse({ status: 404 });

				try {
					const parsed = await server.verifyAuthentication(authentication, cred.credential, {
						challenge: storage.challenge,
						origin: host,
						userVerified: true,
						counter: cred.authenticator.counter,
					});

					/* 更新 counter（可選）*/
					cred.authenticator.counter = parsed.newCounter;
					await env.Storage.put(username, JSON.stringify(storage));

					return jsonResponse({ data: parsed });
				} catch (e) {
					return jsonResponse({ status: 400, data: e });
				}
			}
		}

		/* 其餘路徑 */
		return new Response("Not Found", { status: 404, headers: cors });
	},
};
