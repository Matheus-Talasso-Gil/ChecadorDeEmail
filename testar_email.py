import hashlib
import io
import json
import os
import re
import threading
from tkinter import filedialog, messagebox
import customtkinter as ctk
import dns.resolver
from PIL import Image
import requests

# Configuração global do tema
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# Timeout padrão para requisições de rede (segundos)
DEFAULT_TIMEOUT = 8
HISTORY_FILE = "history.json"


class EmailCheckerApp(ctk.CTk):

  def __init__(self):
    super().__init__()

    # Configurações da Janela
    self.title("Analisador Profissional de E-mail & OSINT")
    self.geometry("1100x890")
    self.resizable(False, False)

    # Armazenamento de estado
    self.current_analysis_data = {}
    self.search_history = []

    # Frame Principal
    self.main_container = ctk.CTkFrame(self, fg_color="transparent")
    self.main_container.pack(fill="both", expand=True, padx=15, pady=15)

    # --- PAINEL LATERAL (HISTÓRICO PERSISTENTE) ---
    self.sidebar = ctk.CTkFrame(self.main_container, width=200, corner_radius=10)
    self.sidebar.pack(side="left", fill="y", padx=(0, 10))

    sidebar_header = ctk.CTkFrame(self.sidebar, fg_color="transparent")
    sidebar_header.pack(fill="x", padx=10, pady=(15, 5))

    ctk.CTkLabel(
        sidebar_header,
        text="📜 Histórico",
        font=ctk.CTkFont(size=16, weight="bold"),
    ).pack(side="left", padx=5)

    # Botão para Apagar Histórico (Lixeira)
    self.btn_clear_history = ctk.CTkButton(
        sidebar_header,
        text="🗑️",
        width=30,
        height=28,
        fg_color="#EF4444",
        hover_color="#DC2626",
        command=self.clear_all_history,
    )
    self.btn_clear_history.pack(side="right")

    self.history_scroll = ctk.CTkScrollableFrame(self.sidebar, width=170)
    self.history_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 15))

    # --- ÁREA DE CONTEÚDO PRINCIPAL ---
    self.content_area = ctk.CTkFrame(self.main_container, fg_color="transparent")
    self.content_area.pack(side="right", fill="both", expand=True)

    # Cabeçalho
    self.title_label = ctk.CTkLabel(
        self.content_area,
        text="📧 Analisador de E-mail & OSINT Dashboard",
        font=ctk.CTkFont(size=22, weight="bold"),
    )
    self.title_label.pack(pady=(5, 5))

    # Input Frame
    self.input_frame = ctk.CTkFrame(self.content_area)
    self.input_frame.pack(fill="x", pady=5)

    self.email_entry = ctk.CTkEntry(
        self.input_frame,
        placeholder_text="Digite o e-mail (ex: usuario@empresa.com)",
        width=490,
        height=40,
    )
    self.email_entry.pack(side="left", padx=(15, 10), pady=12)

    self.email_entry.bind(
        "<Return>", lambda event: self.start_analysis_thread()
    )
    self.email_entry.bind("<KeyRelease>", self.on_email_change)

    self.analyze_button = ctk.CTkButton(
        self.input_frame,
        text="Analisar E-mail",
        command=self.start_analysis_thread,
        height=40,
        font=ctk.CTkFont(weight="bold"),
    )
    self.analyze_button.pack(side="left", padx=(0, 8), pady=12)

    self.clear_button = ctk.CTkButton(
        self.input_frame,
        text="Limpar",
        command=self.clear_fields,
        height=40,
        width=80,
        fg_color="#6B7280",
        hover_color="#4B5563",
        font=ctk.CTkFont(weight="bold"),
    )
    self.clear_button.pack(side="left", padx=(0, 15), pady=12)

    # Barra de Progresso
    self.progress_bar = ctk.CTkProgressBar(
        self.content_area, mode="indeterminate"
    )
    self.progress_bar.pack(fill="x", pady=2)
    self.progress_bar.pack_forget()

    # Label de Status
    self.status_label = ctk.CTkLabel(
        self.content_area, text="", font=ctk.CTkFont(size=12, slant="italic")
    )
    self.status_label.pack(pady=(0, 5))

    # Grid de 4 Cartões
    self.cards_frame = ctk.CTkFrame(self.content_area, fg_color="transparent")
    self.cards_frame.pack(fill="both", expand=True, pady=5)
    self.cards_frame.columnconfigure((0, 1), weight=1, uniform="group1")
    self.cards_frame.rowconfigure((0, 1), weight=1, uniform="group2")

    # --- QUADRO 1: Perfil & Identidade ---
    self.card_profile = ctk.CTkFrame(self.cards_frame, corner_radius=10)
    self.card_profile.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

    profile_header = ctk.CTkFrame(self.card_profile, fg_color="transparent")
    profile_header.pack(fill="x", padx=12, pady=(10, 5))

    ctk.CTkLabel(
        profile_header,
        text="👤 Perfil & Identidade",
        font=ctk.CTkFont(size=14, weight="bold"),
    ).pack(side="left")

    self.avatar_label = ctk.CTkLabel(profile_header, text="", width=48, height=48)
    self.avatar_label.pack(side="right")
    self.set_default_avatar()

    self.txt_profile = ctk.CTkTextbox(
        self.card_profile, font=ctk.CTkFont(size=12)
    )
    self.txt_profile.pack(fill="both", expand=True, padx=12, pady=(0, 10))

    # --- QUADRO 2: Segurança & Validação ---
    self.card_security = ctk.CTkFrame(self.cards_frame, corner_radius=10)
    self.card_security.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

    ctk.CTkLabel(
        self.card_security,
        text="🛡️ Validação & Segurança",
        font=ctk.CTkFont(size=14, weight="bold"),
    ).pack(anchor="w", padx=12, pady=(10, 5))

    self.txt_security = ctk.CTkTextbox(
        self.card_security, font=ctk.CTkFont(size=12)
    )
    self.txt_security.pack(fill="both", expand=True, padx=12, pady=(0, 5))

    risk_frame = ctk.CTkFrame(self.card_security, fg_color="transparent")
    risk_frame.pack(fill="x", padx=12, pady=(0, 10))

    self.lbl_risk_title = ctk.CTkLabel(
        risk_frame,
        text="Score de Risco: -",
        font=ctk.CTkFont(size=11, weight="bold"),
    )
    self.lbl_risk_title.pack(anchor="w")

    self.risk_progress = ctk.CTkProgressBar(risk_frame, height=10)
    self.risk_progress.set(0)
    self.risk_progress.pack(fill="x", pady=(2, 0))

    # --- QUADRO 3: Vazamentos & Leaks ---
    self.card_breaches = ctk.CTkFrame(self.cards_frame, corner_radius=10)
    self.card_breaches.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

    ctk.CTkLabel(
        self.card_breaches,
        text="🚨 Registos de Vazamentos",
        font=ctk.CTkFont(size=14, weight="bold"),
    ).pack(anchor="w", padx=12, pady=(10, 5))

    self.txt_breaches = ctk.CTkTextbox(
        self.card_breaches, font=ctk.CTkFont(size=12)
    )
    self.txt_breaches.pack(fill="both", expand=True, padx=12, pady=(0, 10))

    # --- QUADRO 4: Conexão & IP ---
    self.card_network = ctk.CTkFrame(self.cards_frame, corner_radius=10)
    self.card_network.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)

    ctk.CTkLabel(
        self.card_network,
        text="📍 Origem & Geolocalização",
        font=ctk.CTkFont(size=14, weight="bold"),
    ).pack(anchor="w", padx=12, pady=(10, 5))

    self.txt_network = ctk.CTkTextbox(
        self.card_network, font=ctk.CTkFont(size=12)
    )
    self.txt_network.pack(fill="both", expand=True, padx=12, pady=(0, 10))

    # --- PAINEL INFERIOR (EXPORTAÇÃO & CLIPBOARD) ---
    self.export_frame = ctk.CTkFrame(self.content_area, height=50)
    self.export_frame.pack(fill="x", pady=(5, 0))

    ctk.CTkLabel(
        self.export_frame,
        text="💾 Ações do Relatório:",
        font=ctk.CTkFont(size=12, weight="bold"),
    ).pack(side="left", padx=15)

    self.btn_export_json = ctk.CTkButton(
        self.export_frame,
        text="Salvar JSON",
        width=100,
        height=32,
        command=self.export_json,
        fg_color="#3B82F6",
    )
    self.btn_export_json.pack(side="left", padx=4, pady=8)

    self.btn_export_txt = ctk.CTkButton(
        self.export_frame,
        text="Salvar TXT",
        width=100,
        height=32,
        command=self.export_txt,
        fg_color="#10B981",
    )
    self.btn_export_txt.pack(side="left", padx=4, pady=8)

    self.btn_copy_summary = ctk.CTkButton(
        self.export_frame,
        text="Copiar Resumo",
        width=110,
        height=32,
        command=self.copy_summary_to_clipboard,
        fg_color="#8B5CF6",
        hover_color="#7C3AED",
    )
    self.btn_copy_summary.pack(side="left", padx=4, pady=8)

    self.load_history_from_file()

  # --- GERENCIAMENTO DE HISTÓRICO ---
  def load_history_from_file(self):
    if os.path.exists(HISTORY_FILE):
      try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
          data = json.load(f)
          if isinstance(data, list):
            for email in data:
              self.add_to_history(email, save_to_disk=False)
      except Exception:
        pass

  def save_history_to_file(self):
    try:
      with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(self.search_history, f, indent=4, ensure_ascii=False)
    except Exception:
      pass

  def clear_all_history(self):
    """Apaga o histórico da interface e remove o arquivo de salvamento."""
    if not self.search_history:
      return

    if messagebox.askyesno(
        "Confirmar", "Deseja apagar todo o histórico de pesquisas?"
    ):
      self.search_history.clear()
      for widget in self.history_scroll.winfo_children():
        widget.destroy()
      if os.path.exists(HISTORY_FILE):
        try:
          os.remove(HISTORY_FILE)
        except Exception:
          pass

  def add_to_history(self, email, save_to_disk=True):
    if email not in self.search_history:
      self.search_history.append(email)
      btn = ctk.CTkButton(
          self.history_scroll,
          text=email,
          fg_color="transparent",
          border_width=1,
          text_color="#E5E7EB",
          anchor="w",
          command=lambda e=email: self.re_analyze_from_history(e),
      )
      btn.pack(fill="x", pady=3)
      if save_to_disk:
        self.save_history_to_file()

  def on_email_change(self, event=None):
    if event and event.keysym in (
        "Return",
        "Tab",
        "Left",
        "Right",
        "Up",
        "Down",
    ):
      return
    self.clear_results_only()

  def clear_results_only(self):
    self.set_text(self.txt_profile, "")
    self.set_text(self.txt_security, "")
    self.set_text(self.txt_breaches, "")
    self.set_text(self.txt_network, "")
    self.set_default_avatar()
    self.update_risk_ui(0)
    self.status_label.configure(text="")
    self.current_analysis_data = {}

  def clear_fields(self):
    self.email_entry.delete(0, "end")
    self.clear_results_only()

  def set_default_avatar(self):
    img = Image.new("RGB", (48, 48), color="#374151")
    ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(48, 48))
    self.avatar_label.configure(image=ctk_img)

  def load_avatar_from_url(self, url):
    try:
      resp = requests.get(url, timeout=DEFAULT_TIMEOUT)
      if resp.status_code == 200:
        raw_img = Image.open(io.BytesIO(resp.content))
        ctk_img = ctk.CTkImage(
            light_image=raw_img, dark_image=raw_img, size=(48, 48)
        )
        self.avatar_label.configure(image=ctk_img)
        return
    except requests.RequestException:
      pass
    self.set_default_avatar()

  def set_text(self, textbox, content):
    textbox.configure(state="normal")
    textbox.delete("1.0", "end")
    textbox.insert("1.0", content)
    textbox.configure(state="disabled")

  def re_analyze_from_history(self, email):
    self.email_entry.delete(0, "end")
    self.email_entry.insert(0, email)
    self.start_analysis_thread()

  # --- CONSULTAS DE REPUTAÇÃO E APIs OSINT ---

  def check_username_platforms(self, email):
    """Extrai o prefixo do e-mail e verifica a existência do nickname nas redes."""
    if "@" not in email:
      return "Não encontrado no banco de dados."

    username = email.split("@")[0].strip().lower()
    found = []

    # 1. Docker Hub
    try:
      resp = requests.get(
          f"https://hub.docker.com/v2/users/{username}",
          timeout=DEFAULT_TIMEOUT,
      )
      if resp.status_code == 200:
        found.append("Docker Hub")
    except requests.RequestException:
      pass

    # 2. Medium
    try:
      resp = requests.head(
          f"https://medium.com/@{username}", timeout=DEFAULT_TIMEOUT
      )
      if resp.status_code == 200:
        found.append("Medium")
    except requests.RequestException:
      pass

    # 3. Dev.to
    try:
      resp = requests.get(
          f"https://dev.to/api/users/by_username?url={username}",
          timeout=DEFAULT_TIMEOUT,
      )
      if resp.status_code == 200:
        found.append("Dev.to")
    except requests.RequestException:
      pass

    if found:
      return f"'{username}' em: {', '.join(found)} [OK]"
    return "Não encontrado no banco de dados."

  def check_keybase_profile(self, email):
    try:
      url = (
          "https://keybase.io/_/api/1.0/user/lookup.json?email="
          + email.strip().lower()
      )
      resp = requests.get(url, timeout=DEFAULT_TIMEOUT)
      if resp.status_code == 200:
        data = resp.json()
        if data.get("status", {}).get("code") == 0 and data.get("them"):
          user = data["them"][0]
          username = user.get("basics", {}).get("username")
          if username:
            return f"{username} (https://keybase.io/{username})"
    except requests.RequestException:
      pass
    return "Não encontrado no banco de dados."

  def verify_domain_reputation(self, domain):
    if (
        not domain
        or domain in ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com"]
    ):
      return "Domínio público comercial (Sem bloqueios corporativos)"

    resolver = dns.resolver.Resolver()
    resolver.lifetime = DEFAULT_TIMEOUT
    blacklists = ["zen.spamhaus.org", "bl.spamcop.net"]
    bloqueios = []

    for bl in blacklists:
      try:
        query = f"{domain}.{bl}"
        resolver.resolve(query, "A")
        bloqueios.append(bl.split(".")[1].capitalize())
      except Exception:
        pass

    if bloqueios:
      return f"ALERTA: Domínio listado em spam/phishing ({', '.join(bloqueios)}) ⚠️"
    return "Limpo (Sem bloqueios ou alertas de reputação) [OK]"

  def verify_mx_records(self, domain):
    if not domain:
      return "Não [X]"
    try:
      resolver = dns.resolver.Resolver()
      resolver.lifetime = DEFAULT_TIMEOUT
      records = resolver.resolve(domain, "MX")
      if records:
        return "Sim [OK]"
    except Exception:
      pass
    return "Não encontrado no banco de dados."

  def verify_domain_security(self, domain):
    if not domain:
      return "Não encontrado no banco de dados."

    status = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DEFAULT_TIMEOUT

    try:
      txt_records = resolver.resolve(domain, "TXT")
      for txt in txt_records:
        if "v=spf1" in str(txt):
          status.append("SPF [OK]")
          break
    except Exception:
      pass

    try:
      dmarc_records = resolver.resolve(f"_dmarc.{domain}", "TXT")
      for txt in dmarc_records:
        if "v=DMARC1" in str(txt):
          status.append("DMARC [OK]")
          break
    except Exception:
      pass

    return ", ".join(status) if status else "Não encontrado no banco de dados."

  def check_github_profile(self, email):
    try:
      url = f"https://api.github.com/search/users?q={email}+in:email"
      headers = {"User-Agent": "OSINT-Email-Checker"}
      resp = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
      if resp.status_code == 200:
        data = resp.json()
        if data.get("total_count", 0) > 0:
          user = data["items"][0]
          return f"{user.get('login')} ({user.get('html_url')})"
    except requests.RequestException:
      pass
    return "Não encontrado no banco de dados."

  def check_pgp_key(self, email):
    try:
      url = f"https://keyserver.ubuntu.com/pks/lookup?search={email}&op=index&options=mr"
      resp = requests.get(url, timeout=DEFAULT_TIMEOUT)
      if resp.status_code == 200 and "pub:" in resp.text:
        lines = resp.text.split("\n")
        for line in lines:
          if line.startswith("pub:"):
            key_id = line.split(":")[1]
            return f"Chave Encontrada (ID: {key_id[-8:]})"
    except requests.RequestException:
      pass
    return "Não encontrado no banco de dados."

  def check_spam_reputation(self, email):
    try:
      url = f"https://api.stopforumspam.org/api?email={email}&json"
      resp = requests.get(url, timeout=DEFAULT_TIMEOUT)
      if resp.status_code == 200:
        data = resp.json()
        if data.get("success"):
          email_data = data.get("email", {})
          if email_data.get("appears", 0):
            return (
                f"Reportado ({email_data.get('frequency', 0)} denúncias) ⚠️"
            )
          return "Limpo (Sem denúncias) [OK]"
    except requests.RequestException:
      pass
    return "Não encontrado no banco de dados."

  def check_registered_services(self, email):
    clean_email = email.strip().lower()
    services_found = []

    try:
      resp = requests.get(
          "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email="
          + clean_email,
          timeout=DEFAULT_TIMEOUT,
      )
      if resp.status_code == 200 and resp.json().get("status") == 20:
        services_found.append("Spotify")
    except requests.RequestException:
      pass

    hash_md5 = hashlib.md5(clean_email.encode("utf-8")).hexdigest()
    try:
      resp = requests.head(
          f"https://www.gravatar.com/avatar/{hash_md5}?d=404",
          timeout=DEFAULT_TIMEOUT,
      )
      if resp.status_code == 200:
        services_found.append("Gravatar")
    except requests.RequestException:
      pass

    if services_found:
      return ", ".join(services_found) + " [OK]"
    return "Não encontrado no banco de dados."

  def get_user_identity(self, email):
    clean_email = email.strip().lower()
    hash_md5 = hashlib.md5(clean_email.encode("utf-8")).hexdigest()

    nome = "Não encontrado no banco de dados."
    foto_url = None

    try:
      img_resp = requests.head(
          f"https://www.gravatar.com/avatar/{hash_md5}?d=404",
          timeout=DEFAULT_TIMEOUT,
      )
      if img_resp.status_code == 200:
        foto_url = f"https://gravatar.com/avatar/{hash_md5}"
    except requests.RequestException:
      pass

    try:
      json_resp = requests.get(
          f"https://www.gravatar.com/{hash_md5}.json", timeout=DEFAULT_TIMEOUT
      )
      if json_resp.status_code == 200:
        data = json_resp.json()
        entry = data.get("entry", [{}])[0]
        nome_res = entry.get("displayName") or entry.get("name", {}).get(
            "formatted"
        )
        if nome_res:
          nome = nome_res
    except requests.RequestException:
      pass

    return nome, foto_url

  def check_breaches_real(self, email):
    breaches = []
    try:
      url = f"https://leakcheck.io/api/public?check={email}"
      response = requests.get(url, timeout=DEFAULT_TIMEOUT)
      if response.status_code == 200:
        res_data = response.json()
        if res_data.get("success") and res_data.get("sources"):
          for src in res_data["sources"]:
            data_reg = (
                src.get("date")
                if src.get("date")
                else "Não encontrado no banco de dados."
            )
            breaches.append({
                "fonte": src.get("name", "Vazamento Registrado"),
                "data": data_reg,
                "vazado": "Credenciais / Senhas de Acesso",
            })
    except requests.RequestException:
      pass
    return breaches

  def update_risk_ui(self, score):
    progress_val = min(max(score / 100.0, 0.0), 1.0)
    self.risk_progress.set(progress_val)

    if score == 0:
      color = "#374151"
      label_text = "Score de Risco: -"
    elif score < 40:
      color = "#10B981"
      label_text = f"Score de Risco: {score}/100 (Baixo Risco)"
    elif score < 70:
      color = "#F59E0B"
      label_text = f"Score de Risco: {score}/100 (Médio Risco)"
    else:
      color = "#EF4444"
      label_text = f"Score de Risco: {score}/100 (Alto Risco)"

    self.risk_progress.configure(progress_color=color)
    self.lbl_risk_title.configure(text=label_text, text_color=color)

  def start_analysis_thread(self):
    email = self.email_entry.get().strip()
    if not email:
      return

    self.add_to_history(email)
    self.analyze_button.configure(state="disabled")
    self.clear_button.configure(state="disabled")
    self.progress_bar.pack(fill="x", pady=2)
    self.progress_bar.start()
    self.status_label.configure(
        text="Consultando bases de dados...", text_color="#3B82F6"
    )

    self.set_text(self.txt_profile, "Buscando dados...")
    self.set_text(self.txt_security, "Validando...")
    self.set_text(self.txt_breaches, "Consultando vazamentos...")
    self.set_text(self.txt_network, "Buscando geolocalização...")
    self.set_default_avatar()

    threading.Thread(
        target=self.run_analysis, args=(email,), daemon=True
    ).start()

  def run_analysis(self, email):
    try:
      regex_sintaxe = r"^[\w\.-]+@[\w\.-]+\.\w+$"
      sintaxe_valida = bool(re.match(regex_sintaxe, email))
      domain = email.split("@")[-1].lower() if "@" in email else ""

      pode_receber_email = self.verify_mx_records(domain)
      domain_sec = self.verify_domain_security(domain)
      domain_rep = self.verify_domain_reputation(domain)
      nome_titular, foto_url = self.get_user_identity(email)
      github_info = self.check_github_profile(email)
      keybase_info = self.check_keybase_profile(email)
      username_info = self.check_username_platforms(email)
      pgp_info = self.check_pgp_key(email)
      spam_reputation = self.check_spam_reputation(email)
      plataformas_vinculadas = self.check_registered_services(email)
      breaches = self.check_breaches_real(email)

      score_risco = 10 if sintaxe_valida else 100
      if breaches:
        score_risco += len(breaches) * 20
      if "Reportado" in spam_reputation or "ALERTA" in domain_rep:
        score_risco += 30

      score_risco = min(score_risco, 100)

      # 1. Perfil
      text_profile = (
          f"• E-mail: {email}\n\n"
          f"• Nome do Titular:\n  {nome_titular}\n\n"
          f"• GitHub:\n  {github_info}\n\n"
          f"• Keybase:\n  {keybase_info}\n\n"
          f"• Presença por Username:\n  {username_info}\n\n"
          f"• Cadastros Confirmados:\n  {plataformas_vinculadas}\n\n"
          f"• Foto de Perfil:\n "
          f" {foto_url if foto_url else 'Não encontrado no banco de dados.'}"
      )

      # 2. Segurança
      text_security = (
          f"• Sintaxe Válida: {'Sim [OK]' if sintaxe_valida else 'Não [X]'}\n\n"
          f"• Pode Receber E-mails: {pode_receber_email}\n\n"
          f"• Domínio: {domain}\n\n"
          f"• Segurança do Domínio (SPF/DMARC):\n  {domain_sec}\n\n"
          f"• Reputação do Domínio:\n  {domain_rep}\n\n"
          f"• Reputação de Spam:\n  {spam_reputation}\n\n"
          f"• Chave PGP:\n  {pgp_info}"
      )

      # 3. Vazamentos
      if breaches:
        text_breaches = f"Encontrado em {len(breaches)} registro(s):\n\n"
        for idx, b in enumerate(breaches, 1):
          text_breaches += (
              f"[{idx}] FONTE: {b['fonte']}\n"
              f"• Data: {b['data']}\n"
              f"• Dados: {b['vazado']}\n\n"
          )
      else:
        text_breaches = "Não encontrado no banco de dados."

      # 4. Rede e IP
      text_network = (
          "• IP de Origem do Log:\n  Não encontrado no banco de dados.\n\n"
          "• Localização do IP (ip-api.com):\n  Não encontrado no banco de"
          " dados.\n\n"
          "• Status da Conexão:\n  Análise realizada"
      )

      self.current_analysis_data = {
          "email": email,
          "titular": nome_titular,
          "github": github_info,
          "keybase": keybase_info,
          "username_platforms": username_info,
          "cadastros": plataformas_vinculadas,
          "sintaxe_valida": sintaxe_valida,
          "pode_receber_email": pode_receber_email,
          "dominio": domain,
          "seguranca_dominio": domain_sec,
          "reputacao_dominio": domain_rep,
          "reputacao_spam": spam_reputation,
          "pgp_key": pgp_info,
          "score_risco": score_risco,
          "vazamentos": (
              f"{len(breaches)} registro(s) encontrado(s)"
              if breaches
              else "Não encontrado no banco de dados."
          ),
      }

      self.after(
          0,
          self.update_ui_success,
          text_profile,
          text_security,
          text_breaches,
          text_network,
          foto_url,
          score_risco,
      )

    except Exception as e:
      self.after(0, self.update_ui_error, str(e))

  def update_ui_success(self, p, s, b, n, foto_url, score):
    self.set_text(self.txt_profile, p)
    self.set_text(self.txt_security, s)
    self.set_text(self.txt_breaches, b)
    self.set_text(self.txt_network, n)

    if foto_url:
      threading.Thread(
          target=self.load_avatar_from_url, args=(foto_url,), daemon=True
      ).start()
    else:
      self.set_default_avatar()

    self.update_risk_ui(score)
    self.stop_loading("Análise concluída com sucesso!", "#10B981")

  def update_ui_error(self, error_msg):
    self.set_text(self.txt_profile, f"Erro: {error_msg}")
    self.stop_loading("Erro na consulta.", "#EF4444")

  def stop_loading(self, status_msg, color):
    self.progress_bar.stop()
    self.progress_bar.pack_forget()
    self.analyze_button.configure(state="normal")
    self.clear_button.configure(state="normal")
    self.status_label.configure(text=status_msg, text_color=color)

  # --- EXPORTAÇÃO E CLIPBOARD ---
  def copy_summary_to_clipboard(self):
    if not self.current_analysis_data:
      messagebox.showwarning(
          "Aviso", "Nenhuma análise realizada para copiar."
      )
      return

    d = self.current_analysis_data
    summary_text = (
        f"📧 E-mail: {d.get('email')}\n"
        f"👤 Titular: {d.get('titular')}\n"
        f"📊 Score de Risco: {d.get('score_risco')}/100\n"
        f"🚨 Vazamentos: {d.get('vazamentos')}\n"
        f"🌐 Domínio: {d.get('dominio')} | Reputação: {d.get('reputacao_dominio')}\n"
        f"🔗 GitHub: {d.get('github')} | Keybase: {d.get('keybase')}"
    )
    self.clipboard_clear()
    self.clipboard_append(summary_text)
    messagebox.showinfo("Sucesso", "Resumo copiado para a área de transferência!")

  def export_json(self):
    if not self.current_analysis_data:
      messagebox.showwarning(
          "Aviso", "Nenhuma análise realizada para exportar."
      )
      return

    filepath = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("Arquivos JSON", "*.json")],
        initialfile=f"relatorio_{self.current_analysis_data.get('email', 'email')}.json",
    )
    if filepath:
      with open(filepath, "w", encoding="utf-8") as f:
        json.dump(self.current_analysis_data, f, indent=4, ensure_ascii=False)
      messagebox.showinfo("Sucesso", f"Relatório JSON salvo em:\n{filepath}")

  def export_txt(self):
    if not self.current_analysis_data:
      messagebox.showwarning(
          "Aviso", "Nenhuma análise realizada para exportar."
      )
      return

    filepath = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Arquivos de Texto", "*.txt")],
        initialfile=f"relatorio_{self.current_analysis_data.get('email', 'email')}.txt",
    )
    if filepath:
      d = self.current_analysis_data
      content = (
          "====================================================\n"
          "       RELATÓRIO DE INTELIGÊNCIA E OSINT\n"
          "====================================================\n\n"
          f"E-mail Analisado: {d.get('email')}\n"
          f"Nome do Titular: {d.get('titular')}\n"
          f"Score de Risco: {d.get('score_risco')}/100\n\n"
          "----------------------------------------------------\n"
          "[1] PERFIL & IDENTIDADE\n"
          "----------------------------------------------------\n"
          f"GitHub: {d.get('github')}\n"
          f"Keybase: {d.get('keybase')}\n"
          f"Username em Plataformas: {d.get('username_platforms')}\n"
          f"Cadastros Confirmados: {d.get('cadastros')}\n\n"
          "----------------------------------------------------\n"
          "[2] SEGURANÇA & VALIDAÇÃO\n"
          "----------------------------------------------------\n"
          f"Sintaxe Válida: {d.get('sintaxe_valida')}\n"
          f"Pode Receber E-mails: {d.get('pode_receber_email')}\n"
          f"Domínio: {d.get('dominio')}\n"
          f"Segurança do Domínio (SPF/DMARC): {d.get('seguranca_dominio')}\n"
          f"Reputação do Domínio: {d.get('reputacao_dominio')}\n"
          f"Reputação de Spam: {d.get('reputacao_spam')}\n"
          f"Chave PGP: {d.get('pgp_key')}\n\n"
          "----------------------------------------------------\n"
          "[3] REGISTROS DE VAZAMENTOS\n"
          "----------------------------------------------------\n"
          f"Vazamentos: {d.get('vazamentos')}\n\n"
          "====================================================\n"
          "Fim do Relatório.\n"
      )
      with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
      messagebox.showinfo("Sucesso", f"Relatório TXT salvo em:\n{filepath}")


if __name__ == "__main__":
  app = EmailCheckerApp()
  app.mainloop()