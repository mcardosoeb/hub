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

## Imagens dos projetos

Cada card mostra uma **prévia gerada automaticamente a partir do site** (um "print" da página):
- Ao adicionar um projeto, a prévia é gerada sozinha em segundo plano.
- É capturada pelo [Microlink](https://microlink.io) (ou pelo [thum.io](https://thum.io), se o primeiro falhar), reduzida para 480×300
  e salva **criptografada** dentro do `data.json`. Assim os serviços externos só são chamados ao gerar, não a cada visita.
- Se o app estava "dormindo" no Railway e o print saiu como tela de carregamento, use **✏️ Editar → ⟳** no card
  (ou **🔄 Gerar a partir do site** no formulário) para gerar de novo.
- Também dá para **enviar uma imagem própria** no formulário do projeto.
- Se a prévia falhar, o card mostra a inicial do nome num fundo colorido.

O plano grátis do Microlink permite cerca de 50 capturas por dia, o que sobra para uso pessoal.

## Lembrar o PIN

Na tela de PIN, a opção **"Lembrar neste dispositivo (nesta rede/IP)"** (marcada por padrão) faz o hub abrir direto,
sem pedir o PIN, **enquanto você estiver no mesmo navegador e no mesmo IP público**.
- Mudou de rede (ex.: saiu do Wi-Fi de casa e foi para o 4G)? O PIN é pedido de novo, e o novo IP passa a ser o lembrado.
- O botão 🔒 bloqueia o hub **e esquece este dispositivo**.
- Trocar o PIN nas configurações invalida o "lembrar" em todos os outros dispositivos.
- O IP é consultado em [ipify.org](https://www.ipify.org).

## Sobre a segurança do PIN

Como o repositório é público, qualquer pessoa consegue baixar o `data.json` criptografado e tentar adivinhar o PIN offline.
Um PIN de 4–6 dígitos impede o acesso casual, mas não um ataque dedicado. Se os links forem sensíveis, use uma senha
mais longa (letras + números, 10+ caracteres) — o campo aceita qualquer texto. Os apps no Railway continuam acessíveis
por quem souber a URL deles; o PIN protege apenas a lista.

Sobre o "lembrar": como o site é estático (não há servidor), a chave fica guardada no navegador e a checagem de IP
é feita pela própria página. Ela evita que o hub abra sozinho em outra rede, mas alguém com acesso ao seu navegador
desbloqueado conseguiria contornar. Em computador compartilhado, desmarque a opção ou use o 🔒 ao sair.

Os links dos projetos são enviados ao Microlink/thum.io apenas no momento de gerar a prévia.
