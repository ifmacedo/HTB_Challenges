<div align="center">

# ☠️ Hack The Box — Writeups

**Where I break things legally, photograph the crime scene, and write it all down.**
**Onde eu quebro coisas legalmente, fotografo a cena do crime e escrevo tudo.**

[![Boxes](https://img.shields.io/badge/boxes-pwned-brightgreen?style=for-the-badge)](#-the-trophy-shelf)
[![Vibe](https://img.shields.io/badge/vibe-10%25%20skill%20%C2%B7%2090%25%20stubbornness-orange?style=for-the-badge)](#-stats-nobody-asked-for)
[![Fuel](https://img.shields.io/badge/fuel-coffee%E2%98%95-brown?style=for-the-badge)](#-stats-nobody-asked-for)
[![Scope](https://img.shields.io/badge/scope-100%25%20authorized-blue?style=for-the-badge)](#-ground-rules)

**🌎 Language / Idioma &nbsp;→&nbsp; [🇺🇸 English](#en) &nbsp;·&nbsp; [🇧🇷 Português](#pt)**


</div>

---

<a id="en"></a>

# 🇺🇸 English

### 👋 Yo, welcome

This is my trophy shelf of **Hack The Box** machines: how I got in, how I got out with `root.txt`, and every wrong turn in between — because the wrong turns are usually the interesting part.

No "then I reversed the binary like it was a Tuesday afternoon". If something took me four hours and three dead ends, you'll read about all four hours and three dead ends.

**New here?** Grab a coffee, pick a box below, and follow along. **In a hurry?** Every writeup has an attack-path summary at the bottom you can read in 20 seconds.

```
[ you ] ──► [ nmap ] ──► [ "this port is weird" ] ──► [ shell ] ──► [ root ] ──► [ you, 3am, whispering "finally" ]
```

---

### 🏆 The trophy shelf

| Box | OS | Difficulty | The one-line spoiler | Writeup |
|:---|:---:|:---:|:---|:---:|
| **DanglingTree** | 🪟 Windows | 🔴 Hard | The CA advertised certificate templates that **didn't exist**. So I made one exist — and walked out with a Domain Admin certificate. | [📖 Read](DanglingTree/) |
| *your next victim* | — | — | *coming soon™* | ⏳ |
| *the one that humbled me* | — | — | *we don't talk about that one* | 🚧 |

> **Legend:** 🟢 Easy — relaxing · 🟡 Medium — spicy · 🔴 Hard — question your career · 🟣 Insane — question your life choices

---

### 🧪 The recipe (how every writeup here is cooked)

Every story follows the same menu, so you always know where you are:

| Course | What you get |
|:---|:---|
| **1. Recon** | Ports, services, and the one weird thing that ends up mattering |
| **2. Foothold** | The first crack in the wall — with the exact commands |
| **3. Lateral / Privesc** | Every hop, every credential, every "wait, that worked?" |
| **4. Flags** | The money shot 🚩 |
| **5. Remediation** | Because breaking in is easy; explaining how to stop me is the job |
| **6. Attack-path diagram** | The whole chain in one ASCII picture |

Copy-paste friendly. Every command is real, ran on the box, and is written so you can reproduce it — or at least so you can laugh at me for the parts that didn't.

---

### 📜 Ground rules

Breaking into things is only cool when somebody signed the paperwork. So:

- ✅ **Retired boxes only.** HTB asks that live machines aren't spoiled — active flags stay secret. Respect it.
- ✅ **Authorized targets only.** Labs, CTFs, and my own lab. Never anything I don't have permission to poke.
- ✅ **No destructive tricks.** Coerce, don't nuke. No DoS, no wiping logs, no `rm -rf` on someone's domain.
- ✅ **Flags are the receipt, not the point.** The point is the chain and the "why".
- ❌ **No copy-paste walkthroughs.** If I can't explain the step, it doesn't go in the writeup.

---

### 📊 Stats nobody asked for

```
Boxes pwned......................... ██████████████░░░░░░  ongoing
User flags.......................... ✓ (they're the warm-up)
Root flags.......................... ✓ (the victory lap)
VPN forgetting to start............. 47 times
"Let me just grep for 'password'"... 100% success rate
Times nmap was enough.................. 0
Times coffee was the actual tool....... ∞
Boxes where the intended path was easier than my path... all of them
```

---

### 🔬 Currently in the lab

- 🧪 Chasing **ADCS ESC chains** until they stop being magic and start being a checklist
- 🧪 Automating the boring 80% so the fun 20% gets more time
- 🧪 Writing everything down before the memory of it evaporates

---

### 🔗 Connect

| Where | Link |
|:---|:---|
| 📝 **Medium** (long-form writeups) | [@SEU-USUARIO](https://medium.com/@SEU-USUARIO) |
| 🎯 **Hack The Box** | [my profile](https://app.hackthebox.com/profile/SEU-ID) |
| 💼 **LinkedIn** | [in/SEU-USUARIO](https://www.linkedin.com/in/SEU-USUARIO/) |
| 🐙 **GitHub** | you're already here 👀 |

---

<div align="center">

**Found something wrong in a writeup?** Open an issue — I'd rather be corrected than confidently incorrect.

*All content is for education and authorized testing only. Break things you own, or things you have written permission to break.*

`root@pwn:~# whoami` → **someone who reads the docs now** 📚

</div>

<br>

---
---

<a id="pt"></a>

# 🇧🇷 Português

### 👋 E aí, seja bem-vindo(a)

Este é o meu mural de troféus do **Hack The Box**: como eu entrei, como saí com o `root.txt` e todos os caminhos errados no meio — porque normalmente é o caminho errado que rende a história boa.

Nada de "aí eu reverti o binário como quem toma um café". Se me custou quatro horas e três becos sem saída, você vai ler sobre as quatro horas e os três becos.

**Chegou agora?** Pega um café, escolhe uma máquina aí embaixo e vem junto. **Com pressa?** Todo writeup tem um resumo do caminho de ataque no final — dá para ler em 20 segundos.

```
[ você ] ──► [ nmap ] ──► [ "essa porta é estranha" ] ──► [ shell ] ──► [ root ] ──► [ você, 3h da manhã, sussurrando "finalmente" ]
```

---

### 🏆 Mural de troféus

| Máquina | SO | Dificuldade | O spoiler de uma linha | Writeup |
|:---|:---:|:---:|:---|:---:|
| **DanglingTree** | 🪟 Windows | 🔴 Difícil | A CA anunciava templates de certificado que **não existiam**. Então eu fiz um existir — e saí de lá com um certificado de Domain Admin. | [📖 Ler](./DanglingTree/) |
| *a próxima vítima* | — | — | *em breve™* | ⏳ |
| *a que me humilhou* | — | — | *dessa a gente não fala* | 🚧 |

> **Legenda:** 🟢 Fácil — relaxante · 🟡 Médio — temperado · 🔴 Difícil — questione sua carreira · 🟣 Insano — questione suas escolhas de vida

---

### 🧪 A receita (como todo writeup é feito)

Todo texto segue o mesmo menu, então você sempre sabe onde está:

| Etapa | O que você recebe |
|:---|:---|
| **1. Recon** | Portas, serviços e aquela coisinha estranha que no fim era o pulo do gato |
| **2. Foothold** | A primeira rachadura na parede — com os comandos exatos |
| **3. Movimento lateral / Privesc** | Cada pulo, cada credencial, cada "espera… isso funcionou?" |
| **4. Flags** | A cena do dinheiro 🚩 |
| **5. Remediação** | Porque invadir é fácil; explicar como me impedir é o trabalho |
| **6. Diagrama do caminho** | A cadeia inteira numa figura ASCII |

Copiar e colar liberado. Todo comando aqui é real, rodou na máquina e está escrito para você reproduzir — ou pelo menos rir de mim nas partes que não rodaram.

---

### 📜 Regras da casa

Entrar nas coisas só é legal quando alguém assinou o papel. Então:

- ✅ **Só máquinas aposentadas (retired).** A HTB pede que máquinas ativas não sejam entregues — flag de máquina ativa fica em segredo. Respeita isso.
- ✅ **Só alvos autorizados.** Labs, CTFs e o meu próprio laboratório. Nunca nada que eu não tenha permissão de cutucar.
- ✅ **Nada destrutivo.** Coage, não detona. Sem DoS, sem apagar log, sem `rm -rf` no domínio dos outros.
- ✅ **A flag é o recibo, não o objetivo.** O objetivo é a cadeia e o "porquê".
- ❌ **Nada de writeup copiado e colado.** Se eu não sei explicar o passo, ele não entra no texto.

---

### 📊 Estatísticas que ninguém pediu

```
Máquinas dominadas..................... ██████████████░░░░░░ em andamento
User flags............................. ✓ (é o aquecimento)
Root flags............................. ✓ (a volta olímpica)
Esqueci de ligar a VPN................. 47 vezes
"deixa eu só dar um grep em password".. 100% de acerto
Vezes em que o nmap bastou............. 0
Vezes em que o café foi a ferramenta... ∞
Máquinas em que o caminho intended era mais fácil que o meu... todas
```

---

### 🔬 No laboratório agora

- 🧪 Caçando cadeias de ESC do ADCS até pararem de ser magia e virarem checklist
- 🧪 Automatizando os 80% chatos para sobrar tempo para os 20% divertidos
- 🧪 Escrevendo tudo antes que a memória do que eu fiz evapore

---

### 🔗 Contato

| Onde | Link |
|:---|:---|
| 📝 **Medium** (writeups longos) | [@SEU-USUARIO](https://medium.com/@macedo.if) |
| 🎯 **Hack The Box** | [meu perfil](https://app.hackthebox.com/public/users/326902) |
| 💼 **LinkedIn** | [in/SEU-USUARIO](https://www.linkedin.com/in/imacedo-offsec) |
| 🐙 **GitHub** | você já está aqui 👀 |

---

<div align="center">

**Achou algo errado num writeup?** Abre uma issue — prefiro ser corrigido a ficar confiante e errado.

*Todo o conteúdo é para estudo e testes autorizados. Quebre o que é seu, ou o que você tem autorização por escrito para quebrar.*

`root@pwn:~# whoami` → **alguém que agora lê a documentação** 📚

</div>
