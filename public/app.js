const statusElement =
  document.getElementById("status");

async function refreshSessionStatus() {
  try {
    const response =
      await fetch("/api/me", {
        credentials: "same-origin"
      });

    const user =
      response.ok
        ? await response.json()
        : null;

    statusElement.textContent = user
      ? `Sessão de ${
          user.email ??
          user.displayName
        }.`
      : "Nenhuma sessão neste navegador.";
  } catch {
    statusElement.textContent =
      "Nenhuma sessão neste navegador.";
  }
}

const logoutForm =
  document.querySelector(
    'form[action="/oauth/logout"]'
  );

if (logoutForm) {
  logoutForm.addEventListener(
    "submit",
    async (event) => {
      event.preventDefault();

      try {
        const response =
          await fetch("/oauth/logout", {
            method: "POST",
            credentials: "same-origin"
          });

        if (
          response.ok ||
          response.status === 204
        ) {
          statusElement.textContent =
            "Nenhuma sessão neste navegador.";
          await refreshSessionStatus();
        }
      } catch {
        statusElement.textContent =
          "Nenhuma sessão neste navegador.";
      }
    }
  );
}

refreshSessionStatus();