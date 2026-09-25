export function getProviderConfig(provider, env) {
  if (provider === "google") {
    return {
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
      authorizationEndpoint:
        "https://accounts.google.com/o/oauth2/v2/auth",
      tokenEndpoint:
        "https://oauth2.googleapis.com/token",
      redirectUri:
        `${env.PUBLIC_BASE_URL}/oauth/callback/google`
    };
  }

  if (provider === "github") {
    return {
      clientId: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,
      authorizationEndpoint:
        "https://github.com/login/oauth/authorize",
      tokenEndpoint:
        "https://github.com/login/oauth/access_token",
      redirectUri:
        `${env.PUBLIC_BASE_URL}/oauth/callback/github`
    };
  }

  return null;
}

export async function exchangeCode(
  provider,
  env,
  code,
  codeVerifier
) {
  const config = getProviderConfig(provider, env);

  if (!config) {
    throw new Error("Invalid provider");
  }

  const body = new URLSearchParams();

  body.set("client_id", config.clientId);
  body.set("client_secret", config.clientSecret);
  body.set("grant_type", "authorization_code");
  body.set("code", code);
  body.set("redirect_uri", config.redirectUri);
  body.set("code_verifier", codeVerifier);

  const response = await fetch(config.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json"
    },
    body
  });

  if (!response.ok) {
    throw new Error("Token exchange failed");
  }

  return response.json();
}

export async function getGitHubUser(accessToken) {
  const response = await fetch(
    "https://api.github.com/user",
    {
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Accept": "application/vnd.github+json"
      }
    }
  );

  if (!response.ok) {
    throw new Error("GitHub user request failed");
  }

  return response.json();
}

export async function revokeGitHub(
  env,
  accessToken
) {
  const credentials =
    `${env.GITHUB_CLIENT_ID}:${env.GITHUB_CLIENT_SECRET}`;

  const basic = btoa(credentials);

  const response = await fetch(
    `https://api.github.com/applications/${encodeURIComponent(
      env.GITHUB_CLIENT_ID
    )}/grant`,
    {
      method: "DELETE",
      headers: {
        "Authorization": `Basic ${basic}`,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        access_token: accessToken
      })
    }
  );

  if (response.status !== 204) {
    throw new Error(
      "GitHub authorization revocation failed"
    );
  }
}