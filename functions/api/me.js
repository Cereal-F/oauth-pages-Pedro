import { getCookie } from "../_shared/cookies.js";
import { sha256 } from "../_shared/crypto.js";

export async function onRequestGet(context) {
  try {
    const cookie = getCookie(
      context.request,
      "__Host-session"
    );

    if (!cookie) {
      return new Response("Unauthorized", {
        status: 401,
        headers: {
          "Cache-Control": "no-store"
        }
      });
    }

    const idHash = await sha256(cookie);

    const now = Math.floor(Date.now() / 1000);

    const result = await context.env.DB
      .prepare(`
        SELECT email, display_name, expires_at
        FROM sessions
        WHERE id_hash = ?
          AND expires_at > ?
      `)
      .bind(idHash, now)
      .first();

    if (!result) {
      return new Response("Unauthorized", {
        status: 401,
        headers: {
          "Cache-Control": "no-store"
        }
      });
    }

    return Response.json(
      {
        email: result.email,
        displayName: result.display_name
      },
      {
        headers: {
          "Cache-Control": "no-store"
        }
      }
    );
  } catch {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "Cache-Control": "no-store"
      }
    });
  }
}
