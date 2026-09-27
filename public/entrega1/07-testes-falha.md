# Testes de falha — Laboratório OAuth

## Caso 1 — Retorno sem cookie temporário

- Preparação: Foi iniciado um fluxo de autenticação e o retorno foi realizado sem o cookie temporário esperado.
- Pedido enviado: Retorno OAuth para a rota `/oauth/callback/google` sem o cookie temporário da transação.
- Resultado esperado: A aplicação recusa o retorno e não cria uma sessão.
- Resultado observado: A aplicação recusou o retorno e nenhuma sessão foi criada.

## Caso 2 — State alterado

- Preparação: Foi iniciado um fluxo OAuth e o parâmetro `state` do retorno foi alterado.
- Pedido enviado: Retorno OAuth com valor de `state` diferente daquele associado à transação.
- Resultado esperado: A aplicação recusa o retorno antes de trocar o código.
- Resultado observado: A aplicação recusou o retorno e o código não foi trocado por tokens.

## Caso 3 — Reutilização da transação

- Preparação: Foi realizado um fluxo OAuth válido e a mesma transação foi utilizada novamente.
- Pedido enviado: Novo retorno utilizando uma transação que já havia sido consumida.
- Resultado esperado: A transação já utilizada é recusada.
- Resultado observado: A aplicação recusou a reutilização da transação e não criou uma nova sessão.

## Caso 4 — Sessão expirada

- Preparação: Foi utilizada uma sessão que já estava expirada.
- Pedido enviado: Consulta de `/api/me` utilizando a sessão expirada.
- Resultado esperado: `/api/me` responde 401.
- Resultado observado: `/api/me` respondeu 401 e a sessão expirada não foi aceita.

## Caso 5 — Origin inválida no logout

- Preparação: Foi utilizada uma sessão válida e enviado um pedido de logout com uma origem diferente de `PUBLIC_BASE_URL`.
- Pedido enviado: `POST /oauth/logout` com Origin inválida.
- Resultado esperado: A saída é recusada e a sessão original continua válida.
- Resultado observado: O logout foi recusado e a sessão original permaneceu válida.

## Caso 6 — Reutilização do cookie revogado

- Preparação: Foi realizado o logout de uma sessão válida e tentou-se reutilizar posteriormente o mesmo cookie de sessão.
- Pedido enviado: Consulta de `/api/me` utilizando o cookie de sessão que já havia sido revogado.
- Resultado esperado: `/api/me` responde 401.
- Resultado observado: `/api/me` respondeu 401 e o cookie revogado não restaurou a sessão.
