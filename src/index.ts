import { server } from "@passwordless-id/webauthn";
import { AuthenticationEncoded, RegistrationEncoded, RegistrationParsed } from "@passwordless-id/webauthn/src/types";
import { randomChallenge } from "./utils/challenge"; // 32-byte → base64url

/* ------------ 型別 ------------ */
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

/* ------------ 共用 ------------ */
const cors = {
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Allow-Methods": "GET,POST,OPTIONS",
	"Access-Control-Allow-Headers": "Content-Type",
	"Access-Control-Max-Age": "86400",
};

const jsonResponse = ({ data = {}, status = 200 }: { data?: unknown; status?: number }): Response =>
	new Response(JSON.stringify(data), {
		status,
		headers: { ...cors, "Content-Type": "application/json" },
	});

/* ------------ Worker 入口 ------------ */
export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const { pathname, host } = new URL(request.url);

		/* OPTIONS 預檢 */
		if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

		/* -------- 註冊：challenge -------- */
		if (pathname === "/register/challenge") {
			const { username } = (await request.json()) as ChallengeReq;
			if (!username) return jsonResponse({ status: 400 });

			const challenge = randomChallenge();
			const storage: UserStorage = (await env.Storage.get(username, "json")) ?? { challenge: "", credentials: [] };

			await env.Storage.put(username, JSON.stringify({ ...storage, challenge }));
			return new Response(challenge, { status: 200, headers: cors });
		}

		/* -------- 註冊：verify -------- */
		if (pathname === "/register/verify") {
			const { username, registration } = (await request.json()) as RegisterReq;
			if (!username || !registration) return jsonResponse({ status: 400 });

			const storage = await env.Storage.get<UserStorage>(username, "json");
			if (!storage?.challenge) return jsonResponse({ status: 410 });

			try {
				const parsed = await server.verifyRegistration(registration, {
					challenge: storage.challenge,
					origin: request.headers.get("Origin") ?? host,
				});

				await env.Storage.put(username, JSON.stringify({ ...storage, credentials: [...storage.credentials, parsed] }));
				return jsonResponse({ status: 200 });
			} catch (e) {
				return jsonResponse({
					status: 400,
					data: { name: e.name, message: e.message, ...(e.details && { details: e.details }) },
				});
			}
		}

		/* -------- 登入：challenge -------- */
		if (pathname === "/login/challenge") {
			const { username } = (await request.json()) as ChallengeReq;
			if (!username) return jsonResponse({ status: 400 });

			const storage = await env.Storage.get<UserStorage>(username, "json");
			if (!storage?.credentials.length) return jsonResponse({ status: 404 });

			const challenge = randomChallenge();
			await env.Storage.put(username, JSON.stringify({ ...storage, challenge }));

			return jsonResponse({
				data: { challenge, credentialIds: storage.credentials.map((c) => c.credential.id) },
			});
		}

		/* -------- 登入：verify -------- */
		if (pathname === "/login/verify") {
			const { username, authentication } = (await request.json()) as LoginReq;
			if (!username || !authentication) return jsonResponse({ status: 400 });

			const storage = await env.Storage.get<UserStorage>(username, "json");
			if (!storage?.challenge) return jsonResponse({ status: 410 });

			const cred = storage.credentials.find((c) => c.credential.id === authentication.credentialId);
			if (!cred) return jsonResponse({ status: 404 });

			/* 只在舊 counter > 0 時才檢查，避免 0 → 0 報錯 */
			const expected: any = {
				challenge: storage.challenge,
				origin: request.headers.get("Origin") ?? host,
				userVerified: true,
			};
			if (cred.authenticator.counter > 0) expected.counter = cred.authenticator.counter;

			try {
				const parsed = await server.verifyAuthentication(authentication, cred.credential, expected);

				/* 寫回新 counter（即使仍是 0） */
				cred.authenticator.counter = parsed.newCounter;
				await env.Storage.put(username, JSON.stringify(storage));

				return jsonResponse({ data: parsed });
			} catch (e) {
				return jsonResponse({
					status: 400,
					data: { name: e.name, message: e.message, ...(e.details && { details: e.details }) },
				});
			}
		}

		/* 其他路徑 */
		return new Response("Not Found", { status: 404, headers: cors });
	},
};
