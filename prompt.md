You are an expert in AI security, LLM deployment, and cloud-native architecture. 

Your task is to **design and implement a secure, production-ready framework for running LLM agents** (like OpenClaw or custom LLM agents), packaged in a containerized deployment. The system must be **hardened, auditable, and fully observable**, with built-in **RBAC, policy enforcement, and governance**. Include **unit tests, integration tests, and sample queries** demonstrating secure behavior.

---

### Requirements:

1. Containerized Deployment:
- Package the LLM agent, security modules, and observability tools in **Docker or Kubernetes**.
- Follow **hardened container best practices**: minimal base image, non-root user, secret management, encrypted storage, network restrictions.

2. RBAC (Role-Based Access Control):
- Define roles: Agent, Administrator, Auditor, Developer.
- Enforce **least privilege access** for APIs, secrets, and data stores.

3. Policy Engine & Prompt Injection Protection:
- Implement a **policy engine** that validates all LLM inputs and outputs.
- Detect and **block prompt injections** and secret exfiltration attempts.
- Ensure outputs comply with **security and governance policies**.

4. Governance Framework:
- Maintain **audit trails** for all queries, outputs, and policy decisions.
- Enforce **sensitive data handling rules, output retention, and compliance**.

5. Observability:
- Integrate **OpenTelemetry** for logging, metrics, and tracing.
- Create **dashboards** showing agent usage, RBAC events, policy violations, and health metrics.
- Enable **real-time alerts** for anomalies.

6. Automation & Security Hardening:
- Encrypt data in transit and at rest.
- Validate inputs/outputs and sanitize untrusted content.
- Harden host and container configurations.
- Automate RBAC enforcement, policy checks, and observability setup.

7. Test Coverage:
- **Unit Tests**: Verify policy rules, RBAC enforcement, and secret masking.
- **Integration Tests**: Validate interactions between agent, policy engine, RBAC, and telemetry.
- Include **simulated prompt injection and unauthorized access attempts**.

8. Documentation:
- Generate **README** detailing architecture, deployment, RBAC roles, policy rules, observability, and instructions to run tests.

---

### Output Requirements:
- Hardened **Dockerfile** or **Kubernetes YAML** deployment.
- RBAC configuration files and policy engine rules.
- OpenTelemetry instrumentation with dashboard setup.
- Scripts to start, stop, and test the secure agent.
- Unit and integration test scripts.
- Sample queries showing blocked secret leaks and policy enforcement.
- README with architecture, security, governance, and deployment instructions.

---

Focus on **secure-by-default, modular, auditable, and observable LLM agent operations**. Make the code **production-ready** and **ready to deploy**.

---

## Part 2 — User Interface

You are an expert frontend developer and UI/UX designer.

Your task is to design and generate a **visually soothing, light-themed UI** for a modern web application.

---

### 🎨 Design Goals

- Create a **calm, serene, and minimal interface**
- Prioritize **readability, whitespace, and visual balance**
- Ensure the design feels **modern, elegant, and distraction-free**

---

### 🌿 Theme & Styling

- Use a **light theme** with soft backgrounds:
  - Whites, off-whites (#FAFAFA, #F5F5F5)
  - Pastel tones (light blue, soft green, muted lavender)
- Add **subtle gradients** (very light, not vibrant)
- Avoid harsh contrasts and dark-heavy sections
- Use **soft shadows** and gentle borders
- Apply **glassmorphism lightly** (blur + transparency, but minimal)

---

### 🔤 Typography

- Clean, modern fonts (system UI or sans-serif)
- Strong hierarchy:
  - Clear headings
  - Comfortable body text spacing
- Ensure high readability with proper contrast

---

### 🧩 Components

Design and implement:
- Navbar (minimal, clean)
- Hero section with calm visual hierarchy
- Cards with soft shadows
- Buttons (rounded, subtle hover effects)
- Forms (clean inputs, focus states)
- Footer (simple and elegant)

---

### ✨ Interactions

- Smooth hover effects (scale, opacity, shadow)
- Subtle transitions (no aggressive animations)
- Gentle scroll behavior

---

### 📱 Responsiveness

- Mobile-first design
- Ensure layout adapts cleanly across screen sizes

---

### ⚡ Technical Requirements

- Use **HTML + Tailwind CSS (CDN)**
- Minimal JavaScript
- Clean, semantic HTML structure
- Optimized for performance

---

### 🧠 UX Principles

- Avoid clutter
- Maintain consistent spacing
- Use visual hierarchy to guide attention
- Keep interactions intuitive and predictable

---

### 📦 Output

- Generate a complete `ui/index.html`
- Include all styles inline or via Tailwind CDN
- The UI must connect to the ClawSec API (`/token`, `/query`, `/audit`, `/policy`, `/rbac/roles`)
- Tabs unlock automatically based on the authenticated role's permissions
- Ensure the UI is production-ready and visually polished

---

Focus on creating a **peaceful, Zen-like user experience** that feels effortless and premium.

---

## Part 3 — Configuration Page

You are an expert frontend developer and backend engineer continuing to build ClawSec.

Add a **⚙️ Config** tab to the existing `ui/index.html` and the supporting API endpoints, following the same design language as the rest of the UI (glassmorphism cards, Tailwind, light/pastel theme).

### Backend endpoints (FastAPI, `src/main.py`)

All three endpoints require the `system:admin` permission (administrator role only).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/config` | Returns `safe_view()` (api_key masked) + `PROVIDER_PRESETS` |
| `PATCH` | `/config/{section}` | Merges updates into `llm`, `policy`, or `server` section |
| `POST` | `/config/test` | Sends a minimal test prompt; returns `{success, mode, message}` |

Config changes take effect immediately — no restart required (via `config_manager` singleton).

### UI — Config tab

- **Visible only** when the authenticated user has `system:admin` permission
- **LLM Provider section**
  - Provider preset selector (OpenAI, Groq, Ollama, Anthropic-proxy, Custom) — auto-fills API URL and model
  - API URL text input
  - API Key password input with show/hide toggle; placeholder "leave blank to keep current"
  - Model text input + Max tokens number input (side by side)
  - Timeout seconds input
  - **Save** button (`PATCH /config/llm`)
  - **Test connection** button (`POST /config/test`) — shows inline result below button
  - Mode badge (amber "mock mode" / green "live mode") derived from whether api_url is set
- **Policy Settings section**
  - Four checkboxes: PII filter input, PII filter output, Block prompt injection, Block secret exfiltration
  - **Save policy** button (`PATCH /config/policy`)
- **Server Info section** (read-only key/value display of `server` config section)

### Design requirements
- Match the existing card/section-label/inp/btn-primary CSS classes
- Show toast notifications on save success/failure
- Refresh the mock-mode banner after saving LLM config
- Load config automatically when the tab is first activated (`switchTab('config')` → `loadConfig()`)
- The audit filter dropdown should include `config_updated` as a new option
