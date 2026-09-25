import {
  getCookie,
  clearSessionCookie
} from "../_shared/cookies.js";

import {
  sha256
} from "../_shared/crypto.js";

export async function onRequestPost(context) {
  const origin =
    context.request.headers.get("Origin");

  const referer =
    context.request.headers.get("Referer");

  const requestOrigin =
    origin ??
    (referer ? new URL(referer).origin : null);

  if (
    requestOrigin &&
    requestOrigin !== context.env.PUBLIC_BASE_URL
  ) {
    return new Response(
      "Invalid origin",
      {
        status: 403,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }

  try {
    const cookie =
      getCookie(
        context.request,
        "__Host-session"
      );

    if (cookie) {
      const idHash =
        await sha256(cookie);

      await context.env.DB
        .prepare(`
          DELETE FROM sessions
          WHERE id_hash = ?
        `)
        .bind(idHash)
        .run();
    }

    const response =
      new Response(null, {
        status: 204,
        headers: {
          "Cache-Control": "no-store"
        }
      });

    response.headers.append(
      "Set-Cookie",
      clearSessionCookie()
    );

    return response;
  } catch {
    return new Response(
      "Logout failed",
      {
        status: 500,
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  }
}
``