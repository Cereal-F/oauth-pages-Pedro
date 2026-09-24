import {
  getCookie,
  clearTransactionCookie,
  sessionCookie
} from "../../_shared/cookies.js";

import {
  randomToken,
  sha256
} from "../../_shared/crypto.js";

import {
  exchangeCode,
  getGitHubUser,
  revokeGitHub,
  getProviderConfig
} from "../../_shared/providers.js";

import {
  validateGoogleIdToken
} from "../../_shared/oidc.js";

function errorResponse() {
  return new Response(
    "Authentication failed",
    {
      status: 400,
      headers: {
        "Cache-Control": "no-store"
      }
    }
  );
}

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

  const url =
    new URL(context.request.url);

  const error =
    url.searchParams.get("error");

  const code =
    url.searchParams.get("code");

  const state =
    url.searchParams.get("state");

  if (error || !code || !state) {
    return errorResponse();
  }

  const transactionCookieValue =
    getCookie(
      context.request,
      "__Host-oauth-tx"
    );

  if (!transactionCookieValue) {
    return errorResponse();
  }

  try {
    const transactionHash =
      await sha256(transactionCookieValue);

    const now =
      Math.floor(Date.now() / 1000);

    const transaction =
      await context.env.DB
        .prepare(`
          SELECT
            id_hash,
            provider,
            state_hash,
            nonce,
            code_verifier,
            expires_at
          FROM oauth_transactions
          WHERE id_hash = ?
            AND expires_at > ?
        `)
        .bind(transactionHash, now)
        .first();

    if (!transaction) {
      return errorResponse();
    }

    if (transaction.provider !== provider) {
      return errorResponse();
    }

    const receivedStateHash =
      await sha256(state);

    if (
      receivedStateHash !==
      transaction.state_hash
    ) {
      return errorResponse();
    }

    await context.env.DB
      .prepare(`
        DELETE FROM oauth_transactions
        WHERE id_hash = ?
      `)
      .bind(transactionHash)
      .run();

    const tokens =
      await exchangeCode(
        provider,
        context.env,
        code,
        transaction.code_verifier
      );

    let identity;

    if (provider === "google") {
      if (!tokens.id_token) {
        throw new Error("Missing id_token");
      }

      identity =
        await validateGoogleIdToken(
          tokens.id_token,
          context.env.GOOGLE_CLIENT_ID,
          transaction.nonce
        );
    } else {
      if (
        !tokens.access_token ||
        String(tokens.token_type).toLowerCase() !==
          "bearer"
      ) {
        throw new Error("Invalid GitHub token");
      }

      const githubUser =
        await getGitHubUser(
          tokens.access_token
        );

      if (
        !githubUser ||
        !Number.isInteger(githubUser.id)
      ) {
        throw new Error("Invalid GitHub identity");
      }

      identity = {
        issuer: "https://github.com",
        subject: String(githubUser.id),
        email:
          typeof githubUser.email === "string"
            ? githubUser.email
            : null,
        displayName:
          typeof githubUser.name === "string"
            ? githubUser.name
            : (
                typeof githubUser.login === "string"
                  ? githubUser.login
                  : null
              )
      };

      await revokeGitHub(
        context.env,
        tokens.access_token
      );
    }

    const session =
      randomToken();

    const sessionHash =
      await sha256(session);

    const sessionNow =
      Math.floor(Date.now() / 1000);

    const sessionExpires =
      sessionNow + 28800;

    await context.env.DB
      .prepare(`
        INSERT INTO sessions
        (
          id_hash,
          issuer,
          subject,
          email,
          display_name,
          expires_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        sessionHash,
        identity.issuer,
        identity.subject,
        identity.email,
        identity.displayName,
        sessionExpires,
        sessionNow
      )
      .run();

    const response =
      new Response(null, {
        status: 302,
        headers: {
          "Location":
            context.env.PUBLIC_BASE_URL,
          "Cache-Control":
            "no-store"
        }
      });

    response.headers.append(
      "Set-Cookie",
      clearTransactionCookie()
    );

    response.headers.append(
      "Set-Cookie",
      sessionCookie(session)
    );

    return response;
  } catch {
    return new Response(
      "Authentication failed",
      {
        status: 400,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }
}
