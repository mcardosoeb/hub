# Hub de projetos

Página estática (GitHub Pages) com os links dos meus apps, protegida por PIN.

- Os links ficam em `data.json`, **criptografados** (AES-256-GCM com chave derivada do PIN via PBKDF2, 600 mil iterações).
- Adicionar, editar, reordenar e remover é feito pela própria página, que faz commit do `data.json` pela API do GitHub.
- O token do GitHub **nunca vai para o repositório**: fica só no `localStorage` do navegador onde você o configurou.

## Publicar

1. Crie um repositório no GitHub (ex.: `hub`) e envie os arquivos desta pasta:
   ```powershell
   cd hub
   git init -b main
   git add .
   git commit -m "Hub de projetos"
   git remote add origin https://github.com/SEU-USUARIO/hub.git
   git push -u origin main
   ```
2. No repositório: **Settings → Pages → Source: Deploy from a branch → `main` / `(root)`**.
3. Em ~1 minuto o hub estará em `https://SEU-USUARIO.github.io/hub/`.
   - Se quiser o link mais curto, `https://SEU-USUARIO.github.io`, chame o repositório de `SEU-USUARIO.github.io`.

## Primeiro acesso

1. Abra o link → como ainda não existe `data.json`, a página pede para **criar um PIN**.
2. Crie um token: **GitHub → Settings → Developer settings → Fine-grained tokens → Generate new token**
   - *Repository access*: **Only select repositories** → o repositório do hub
   - *Permissions → Contents*: **Read and write**
   - Defina uma validade (ex.: 1 ano).
3. No hub, ⚙️ **Configurações** → cole o token (usuário/repositório são detectados sozinhos) → Salvar.
   A partir daí, toda alteração gera um commit no `data.json`.

Em outro dispositivo (celular, etc.) basta o PIN para **ver** os links. Para **editar** nele, cole o token uma vez nas configurações.

## Ícones

Para cada projeto você pode usar:
- uma URL de imagem (`https://…/logo.png`),
- um emoji (`🚀`),
- uma imagem enviada do computador (é reduzida para 128px e salva junto, criptografada),
- ou deixar vazio: a página tenta o `/favicon.ico` do próprio app e, se não houver, mostra a inicial do nome.

## Sobre a segurança do PIN

Como o repositório é público, qualquer pessoa consegue baixar o `data.json` criptografado e tentar adivinhar o PIN offline.
Um PIN de 4–6 dígitos impede o acesso casual, mas não um ataque dedicado. Se os links forem sensíveis, use uma senha
mais longa (letras + números, 10+ caracteres) — o campo aceita qualquer texto. Os apps no Railway continuam acessíveis
por quem souber a URL deles; o PIN protege apenas a lista.
