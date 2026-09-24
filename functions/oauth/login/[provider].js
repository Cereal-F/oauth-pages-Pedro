import {
  randomToken,
  sha256,
  pkceChallenge
} from "../../_shared/crypto.js";

import {
  transactionCookie
} from "../../_shared/cookies.js";

import {
  getProviderConfig
} from "../../_shared/providers.js";

export async function onRequestGet(context) {
  const provider = context.params.provider;

  if (
    provider !== "google" &&
    provider !== "github"
  ) {
    return new Response("Not found", {
      status: 404
    });
  }

  try {
    const config =
      getProviderConfig(provider, context.env);

    const transactionId = randomToken();
    const state = randomToken();
    const codeVerifier = randomToken();

    const codeChallenge =
      await pkceChallenge(codeVerifier);

    const nonce =
      provider === "google"
        ? randomToken()
        : null;

    const now =
      Math.floor(Date.now() / 1000);

    const expiresAt = now + 600;

    await context.env.DB
      .prepare(`
        INSERT INTO oauth_transactions
        (
          id_hash,
          provider,
          state_hash,
          nonce,
          code_verifier,
          expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `)
      .bind(
        await sha256(transactionId),
        provider,
        await sha256(state),
        nonce,
        codeVerifier,
        expiresAt
      )
      .run();

    const authorization =
      new URL(config.authorizationEndpoint);

    authorization.searchParams.set(
      "client_id",
      config.clientId
    );

    authorization.searchParams.set(
      "redirect_uri",
      config.redirectUri
    );

    authorization.searchParams.set(
      "response_type",
      "code"
    );

    authorization.searchParams.set(
      "state",
      state
    );

    authorization.searchParams.set(
      "code_challenge",
      codeChallenge
    );

    authorization.searchParams.set(
      "code_challenge_method",
      "S256"
    );

    if (provider === "google") {
      authorization.searchParams.set(
        "scope",
        "openid email profile"
      );

      authorization.searchParams.set(
        "nonce",
        nonce
      );
    }

    const response = new Response(null, {
      status: 302,
      headers: {
        "Location": authorization.toString(),
        "Cache-Control": "no-store"
      }
    });

    response.headers.append(
      "Set-Cookie",
      transactionCookie(transactionId)
    );

    return response;
  } catch {
    return new Response(
      "Unable to start authentication",
      {
        status: 500,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }
}
