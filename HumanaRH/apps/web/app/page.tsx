"use client";

import { useEffect, useState } from "react";
import type { FormEvent } from "react";

type AuthUser = {
  id: string;
  tenantId: string;
  name: string;
  email: string;
};

type AuthResponse = {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  user?: AuthUser;
};

type RestoredSession = {
  accessToken: string;
  user: AuthUser;
};

const API_BASE = (
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001/api"
).replace(/\/+$/, "");

// Compartilha a restauração entre execuções do efeito no React Strict Mode.
let sessionRestorePromise: Promise<RestoredSession | null> | null = null;

async function readJson(response: Response): Promise<Record<string, unknown>> {
  return response.json().catch(() => ({}));
}

function getApiError(data: Record<string, unknown>, fallback: string): string {
  const message = data.message;

  if (Array.isArray(message)) {
    return message.filter((item) => typeof item === "string").join(" ");
  }

  return typeof message === "string" ? message : fallback;
}

async function restoreSession(): Promise<RestoredSession | null> {
  if (!sessionRestorePromise) {
    sessionRestorePromise = (async () => {
      const refreshResponse = await fetch(`${API_BASE}/auth/refresh`, {
        method: "POST",
        credentials: "include",
        headers: { Accept: "application/json" },
      });

      if (!refreshResponse.ok) return null;

      const refreshData = (await readJson(refreshResponse)) as Partial<AuthResponse>;

      if (!refreshData.accessToken) return null;

      const meResponse = await fetch(`${API_BASE}/auth/me`, {
        method: "GET",
        credentials: "include",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${refreshData.accessToken}`,
        },
      });

      if (!meResponse.ok) return null;

      const meData = await readJson(meResponse);
      const user = meData.user as AuthUser | undefined;

      if (!user?.id || !user?.email) return null;

      return {
        accessToken: refreshData.accessToken,
        user,
      };
    })();
  }

  try {
    return await sessionRestorePromise;
  } finally {
    sessionRestorePromise = null;
  }
}

export default function Home() {
  const [tenantSlug, setTenantSlug] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isRestoring, setIsRestoring] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let active = true;

    restoreSession()
      .then((session) => {
        if (!active || !session) return;
        setAccessToken(session.accessToken);
        setUser(session.user);
      })
      .catch(() => {
        if (active) {
          setNotice("Não foi possível restaurar a sessão. Entre novamente.");
        }
      })
      .finally(() => {
        if (active) setIsRestoring(false);
      });

    return () => {
      active = false;
    };
  }, []);

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setNotice("");
    setIsSubmitting(true);

    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          tenantSlug: tenantSlug.trim().toLowerCase(),
          email: email.trim().toLowerCase(),
          password,
        }),
      });

      const data = await readJson(response);

      if (!response.ok) {
        throw new Error(
          getApiError(data, "Não foi possível entrar. Confira seus dados."),
        );
      }

      const result = data as Partial<AuthResponse>;

      if (!result.accessToken || !result.user) {
        throw new Error("A API retornou uma resposta de autenticação incompleta.");
      }

      setAccessToken(result.accessToken);
      setUser(result.user);
      setPassword("");
    } catch (err) {
      setError(
        err instanceof TypeError
          ? "Não foi possível conectar ao servidor. Verifique se a API está em execução."
          : err instanceof Error
            ? err.message
            : "Ocorreu um erro inesperado. Tente novamente.",
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleLogout() {
    setIsLoggingOut(true);

    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: "POST",
        credentials: "include",
        headers: { Accept: "application/json" },
      });
    } finally {
      setAccessToken(null);
      setUser(null);
      setPassword("");
      setIsLoggingOut(false);
      setNotice("Você saiu da sua conta com segurança.");
    }
  }

  if (isRestoring) {
    return (
      <main className="loadingScreen">
        <div className="loadingBrand">
          <span className="brandMark">H</span>
          <span>Humana<strong>RH</strong></span>
        </div>
        <div className="loadingIndicator" />
        <p>Preparando seu ambiente de trabalho...</p>
      </main>
    );
  }

  if (accessToken && user) {
    const firstName = user.name.trim().split(/\s+/)[0] || "Pessoa";

    return (
      <main className="appShell">
        <aside className="sidebar">
          <div className="brand">
            <span className="brandMark">H</span>
            <span>Humana<strong>RH</strong></span>
          </div>

          <div className="workspaceLabel">ESPAÇO DE TRABALHO</div>
          <div className="workspaceCard">
            <span className="workspaceIcon">⌂</span>
            <span>
              <strong>Minha organização</strong>
              <small>Ambiente corporativo</small>
            </span>
            <span className="workspaceChevron">⌄</span>
          </div>

          <div className="navCaption">PLATAFORMA</div>
          <nav className="mainNav" aria-label="Navegação principal">
            <div className="navItem selected"><span>▦</span> Visão geral</div>
            <div className="navItem disabled"><span>♙</span> Pessoas <small>Em breve</small></div>
            <div className="navItem disabled"><span>▤</span> Departamento Pessoal</div>
            <div className="navItem disabled"><span>◷</span> Jornadas e ponto</div>
            <div className="navItem disabled"><span>✓</span> Aprovações</div>
            <div className="navItem disabled"><span>▥</span> Relatórios</div>
          </nav>

          <div className="sidebarBottom">
            <div className="secureNote"><span className="secureDot" /> Conexão protegida</div>
            <div className="sidebarVersion">HUMANARH · AMBIENTE INICIAL</div>
          </div>
        </aside>

        <section className="dashboardContent">
          <header className="topbar">
            <div className="breadcrumb">Início <span>/</span> Visão geral</div>
            <div className="topbarRight">
              <div className="userIdentity">
                <span className="userAvatar">{firstName.slice(0, 1).toUpperCase()}</span>
                <span className="userIdentityText">
                  <strong>{user.name}</strong>
                  <small>{user.email}</small>
                </span>
              </div>
              <button
                className="logoutButton"
                onClick={handleLogout}
                disabled={isLoggingOut}
                type="button"
              >
                {isLoggingOut ? "Saindo..." : "Sair"}
              </button>
            </div>
          </header>

          <div className="dashboardBody">
            <div className="dashboardIntro">
              <div>
                <div className="eyebrow">GESTÃO INTELIGENTE DE PESSOAS</div>
                <h1>Bom dia, {firstName}.</h1>
                <p>Seu espaço de trabalho está pronto para acompanhar a gestão da sua organização.</p>
              </div>
              <div className="dateChip"><span>◷</span> Ambiente seguro</div>
            </div>

            <section className="heroPanel">
              <div className="heroText">
                <span className="heroPill"><span /> PRIMEIROS PASSOS</span>
                <h2>Pessoas no centro.<br />Gestão em outro nível.</h2>
                <p>Estamos construindo uma plataforma completa para conectar pessoas, processos e decisões em um só lugar.</p>
              </div>
              <div className="heroGraphic" aria-hidden="true">
                <div className="heroCircle circleOne" />
                <div className="heroCircle circleTwo" />
                <div className="heroMonogram">H</div>
                <div className="heroSpark">✦</div>
              </div>
            </section>

            <div className="sectionTitle">
              <div>
                <h2>Seu ecossistema de RH</h2>
                <p>Os módulos serão habilitados progressivamente.</p>
              </div>
              <span className="moduleCount">06 MÓDULOS</span>
            </div>

            <div className="moduleGrid">
              <article className="dashboardModule">
                <div className="moduleTop"><span className="moduleIcon">♙</span><span className="moduleStatus">Em preparação</span></div>
                <h3>Pessoas</h3><p>Cadastro, dados e jornada dos colaboradores.</p>
              </article>
              <article className="dashboardModule">
                <div className="moduleTop"><span className="moduleIcon">▤</span><span className="moduleStatus">Em preparação</span></div>
                <h3>Departamento Pessoal</h3><p>Férias, documentos e movimentações.</p>
              </article>
              <article className="dashboardModule">
                <div className="moduleTop"><span className="moduleIcon">◷</span><span className="moduleStatus">Em preparação</span></div>
                <h3>Jornadas e ponto</h3><p>Registros, escalas e banco de horas.</p>
              </article>
              <article className="dashboardModule">
                <div className="moduleTop"><span className="moduleIcon">✓</span><span className="moduleStatus">Em preparação</span></div>
                <h3>Aprovações</h3><p>Solicitações e fluxos de aprovação.</p>
              </article>
              <article className="dashboardModule">
                <div className="moduleTop"><span className="moduleIcon">✧</span><span className="moduleStatus">Em preparação</span></div>
                <h3>Talentos</h3><p>Recrutamento, seleção e desenvolvimento.</p>
              </article>
              <article className="dashboardModule">
                <div className="moduleTop"><span className="moduleIcon">▥</span><span className="moduleStatus">Em preparação</span></div>
                <h3>Indicadores</h3><p>Dashboards e People Analytics.</p>
              </article>
            </div>

            <footer className="dashboardFooter">
              <span>HumanaRH <strong>·</strong> Gestão de pessoas com inteligência.</span>
              <span>Versão 0.2.0 · Fundação da plataforma</span>
            </footer>
          </div>
        </section>
      </main>
    );
  }

  return (
    <main className="loginPage">
      <section className="loginStory">
        <div className="storyBrand">
          <span className="brandMark">H</span>
          <span>Humana<strong>RH</strong></span>
        </div>

        <div className="storyContent">
          <div className="storyEyebrow"><span /> GESTÃO INTELIGENTE DE PESSOAS</div>
          <h1>O futuro da gestão de pessoas começa <em>aqui.</em></h1>
          <p>Uma plataforma integrada para simplificar rotinas, aproximar equipes e transformar a gestão de RH e Departamento Pessoal.</p>

          <div className="storyFeatures">
            <div><span className="featureCheck">✓</span><span>Processos conectados em um só lugar</span></div>
            <div><span className="featureCheck">✓</span><span>Mais clareza para decisões estratégicas</span></div>
            <div><span className="featureCheck">✓</span><span>Segurança e organização para sua empresa</span></div>
          </div>
        </div>

        <div className="storyBottom">
          <div className="storyLine" />
          <span>TECNOLOGIA QUE VALORIZA PESSOAS</span>
        </div>
        <div className="storyDecoration decorationA" />
        <div className="storyDecoration decorationB" />
      </section>

      <section className="loginArea">
        <div className="loginCard">
          <div className="mobileBrand">
            <span className="brandMark">H</span>
            <span>Humana<strong>RH</strong></span>
          </div>

          <div className="loginHeading">
            <div className="loginIcon">↗</div>
            <div className="eyebrow">BEM-VINDO DE VOLTA</div>
            <h2>Acesse sua conta</h2>
            <p>Informe seus dados para entrar no ambiente da sua organização.</p>
          </div>

          {notice && <div className="noticeMessage" role="status">{notice}</div>}
          {error && <div className="errorMessage" role="alert"><span>!</span>{error}</div>}

          <form className="loginForm" onSubmit={handleLogin}>
            <label htmlFor="tenantSlug">Identificador da organização</label>
            <div className="inputWrap">
              <span className="inputIcon">⌂</span>
              <input
                id="tenantSlug"
                name="tenantSlug"
                type="text"
                autoComplete="organization"
                placeholder="Ex.: minha-empresa"
                value={tenantSlug}
                onChange={(event) => setTenantSlug(event.target.value)}
                minLength={3}
                maxLength={60}
                required
              />
            </div>
            <span className="fieldHint">Identificador utilizado no cadastro da organização.</span>

            <label htmlFor="email">E-mail corporativo</label>
            <div className="inputWrap">
              <span className="inputIcon">✉</span>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="username"
                placeholder="voce@empresa.com.br"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                maxLength={254}
                required
              />
            </div>

            <div className="passwordLabel">
              <label htmlFor="password">Senha</label>
            </div>
            <div className="inputWrap">
              <span className="inputIcon">♧</span>
              <input
                id="password"
                name="password"
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                placeholder="Digite sua senha"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                maxLength={128}
                required
              />
              <button
                className="passwordToggle"
                type="button"
                onClick={() => setShowPassword((current) => !current)}
                aria-label={showPassword ? "Ocultar senha" : "Mostrar senha"}
              >
                {showPassword ? "Ocultar" : "Mostrar"}
              </button>
            </div>

            <button className="submitButton" type="submit" disabled={isSubmitting}>
              {isSubmitting ? <><span className="buttonSpinner" /> Verificando acesso...</> : <>Entrar na plataforma <span>→</span></>}
            </button>
          </form>

          <div className="loginSecurity">
            <span className="securityLock">▣</span>
            <span>Seus dados são protegidos por conexão segura.</span>
          </div>
          <div className="loginCopyright">© 2026 HumanaRH. Todos os direitos reservados.</div>
        </div>
      </section>
    </main>
  );
}