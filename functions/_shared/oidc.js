import {
  base64UrlDecode,
  decodeJsonBase64Url
} from "./crypto.js";

const GOOGLE_ISSUER = "https://accounts.google.com";

async function getDiscovery() {
  const response = await fetch(
    "https://accounts.google.com/.well-known/openid-configuration"
  );

  if (!response.ok) {
    throw new Error("OIDC discovery failed");
  }

  return response.json();
}

export async function validateGoogleIdToken(
  idToken,
  expectedClientId,
  expectedNonce
) {
  const parts = idToken.split(".");

  if (parts.length !== 3) {
    throw new Error("Invalid JWT");
  }

  const [encodedHeader, encodedPayload, encodedSignature] =
    parts;

  const header = decodeJsonBase64Url(encodedHeader);
  const payload = decodeJsonBase64Url(encodedPayload);
  const signature = base64UrlDecode(encodedSignature);

  if (header.alg !== "RS256" || !header.kid) {
    throw new Error("Invalid JWT algorithm");
  }

  const discovery = await getDiscovery();

  if (discovery.issuer !== GOOGLE_ISSUER) {
    throw new Error("Invalid issuer configuration");
  }

  const jwksResponse = await fetch(discovery.jwks_uri);

  if (!jwksResponse.ok) {
    throw new Error("JWKS request failed");
  }

  const jwks = await jwksResponse.json();

  const jwk = jwks.keys.find(
    (key) => key.kid === header.kid
  );

  if (!jwk) {
    throw new Error("Signing key not found");
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  const data = new TextEncoder().encode(
    `${encodedHeader}.${encodedPayload}`
  );

  const validSignature =
    await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signature,
      data
    );

  if (!validSignature) {
    throw new Error("Invalid JWT signature");
  }

  const now = Math.floor(Date.now() / 1000);

  if (payload.iss !== GOOGLE_ISSUER) {
    throw new Error("Invalid issuer");
  }

  const audienceValid =
    Array.isArray(payload.aud)
      ? payload.aud.includes(expectedClientId)
      : payload.aud === expectedClientId;

  if (!audienceValid) {
    throw new Error("Invalid audience");
  }

  if (
    Array.isArray(payload.aud) &&
    payload.aud.length > 1 &&
    payload.azp !== expectedClientId
  ) {
    throw new Error("Invalid authorized party");
  }

  if (
    typeof payload.exp !== "number" ||
    payload.exp <= now
  ) {
    throw new Error("Expired token");
  }

  if (
    typeof payload.iat !== "number" ||
    payload.iat > now + 300
  ) {
    throw new Error("Invalid issued-at time");
  }

  if (payload.nonce !== expectedNonce) {
    throw new Error("Invalid nonce");
  }

  if (!payload.sub) {
    throw new Error("Missing subject");
  }

  return {
    issuer: GOOGLE_ISSUER,
    subject: String(payload.sub),
    email:
      typeof payload.email === "string"
        ? payload.email
        : null,
    displayName:
      typeof payload.name === "string"
        ? payload.name
        : null
  };
}
