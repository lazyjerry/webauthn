export function randomChallenge(bytes = 32): string {
	const array = new Uint8Array(bytes);
	crypto.getRandomValues(array);
	// 轉為 base64url（無補 '='、'+'→'-'、'/'→'_'）
	return btoa(String.fromCharCode(...array))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}
