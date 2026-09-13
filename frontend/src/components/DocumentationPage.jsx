import { BookOpen, ExternalLink } from 'lucide-react'

const sections = [
  ['getting-started', 'Getting started'],
  ['scan-modes', 'Scan modes'],
  ['results', 'Understanding results'],
  ['view-code', 'Inspecting code'],
  ['history', 'History & exports'],
  ['troubleshooting', 'Troubleshooting'],
  ['api', 'API reference'],
]

export default function DocumentationPage() {
  return (
    <article className="info-page documentation" aria-labelledby="documentation-title">
      <div className="info-heading"><BookOpen size={26} /><h1 id="documentation-title">ECDAT Documentation</h1></div>
      <p>Discover cryptographic assets, review quantum risk, and plan post-quantum migration.</p>
      <nav className="docs-contents" aria-label="Documentation sections">
        {sections.map(([id, title]) => <a key={id} href={`#${id}`}>{title}</a>)}
      </nav>

      <section id="getting-started" className="info-card">
        <h2>Getting started</h2>
        <ol>
          <li>Choose a scan mode on Home and select your target.</li>
          <li>Start the scan and wait for the dashboard to open. Large targets can take several minutes.</li>
          <li>Review the Cryptographic Inventory, filter findings, and use View Code to inspect evidence.</li>
          <li>Review migration recommendations and export the CycloneDX JSON report.</li>
        </ol>
        <p>The top-left Home menu opens Dashboard, History, and User Profile. Dashboard shows the current scan, or an empty state before your first scan.</p>
      </section>
      <section id="scan-modes" className="info-card">
        <h2>Scan modes</h2>
        <p><strong>Enterprise discovery:</strong> scan live TLS endpoints, certificate/key directories, AWS KMS, Azure Key Vault, GCP KMS, Vault transit, PKCS#11 HSMs, and private repositories. Supply one target or a JSON batch with independent application contexts. Credentials and HSM modules are configured on the backend; see backend/ENTERPRISE.md for setup and permissions.</p>
        <ul>
          <li><strong>Local Folder:</strong> select a folder or upload a ZIP, up to 200 MB. Folders are zipped in your browser before upload.</li>
          <li><strong>GitHub URL:</strong> enter a public repository URL. The backend needs Git and network access to clone it.</li>
          <li><strong>Binary File:</strong> upload a compiled file such as .exe, .dll, .so, .elf, .bin, .dylib, or .sys, up to 100 MB. Findings come from symbols and cryptographic patterns.</li>
          <li><strong>Container:</strong> upload a Docker/OCI .tar archive up to 500 MB, or enter an image tag already available in the server’s Docker daemon. Image-tag scanning requires Docker to be running.</li>
        </ul>
        <p>Source analysis uses Semgrep rules for Python, Java, JavaScript/TypeScript, and C/C++. Dependency scanning checks supported manifests for known cryptographic dependencies.</p>
      </section>
      <section id="results" className="info-card">
        <h2>Understanding results</h2>
        <p>Business context supplies sensitivity, sensitive-data categories, lifetime, migration time, quantum horizon, and business criticality. These determine risk scores and sensitive-data exposure highlights. Cost/latency weights rank migration candidates; measured budgets require supplied benchmark data. Relative estimates are explicitly labeled.</p>
        <p>The dashboard summarizes discovered assets, critical findings, and the proportion identified as PQC algorithms. Use All, Critical Risk, Asymmetric, or Symmetric/Hash filters and search by algorithm, source path, or target PQC.</p>
        <p><strong>Mosca’s inequality: X + Y &gt; Z.</strong> X is the data-sensitivity lifetime, Y is the migration time, and Z is the estimated time until a cryptographically relevant quantum computer. Findings meeting this inequality are classified as critical using the configured estimates; this is a planning model, not an exact prediction.</p>
        <p>Expand Algorithm Distribution and Cryptographic Risk Heatmap for additional views. Target PQC recommendations can include ML-KEM (FIPS 203) for key establishment and ML-DSA (FIPS 204) for signatures. Review recommendations in the context of your application.</p>
      </section>
      <section id="view-code" className="info-card">
        <h2>Inspecting code</h2>
        <p>View Code opens the selected finding’s captured source snippet with line numbers, file location, detection rule, and migration guidance. Snippets are captured during new source scans so temporary uploads and cloned repositories can be cleaned up afterwards.</p>
        <p>Binary findings show symbol and offset evidence instead of source code. Older reports and sample data may not contain snippets; run a new source scan to capture them.</p>
        <p>Source snippets are available for the current scan and included in its JSON export. Saved history excludes source snippets; loading history shows finding metadata, and inspecting source requires a new scan.</p>
      </section>
      <section id="history" className="info-card">
        <h2>History & exports</h2>
        <p>Completed scans are saved to your signed-in account when Supabase is configured. Open History to reload or delete a report. Scan summaries and BOM metadata are stored, with source snippets removed.</p>
        <p>Export CycloneDX JSON downloads the current report. View JSON opens an in-app preview. User Profile displays your account details and provides Sign out.</p>
      </section>
      <section id="troubleshooting" className="info-card">
        <h2>Troubleshooting</h2>
        <ul>
          <li><code>POST /discover</code> — batch discovery targets and business context; validated CycloneDX response with coverage and partial errors.</li>
          <li><strong>API Offline:</strong> check that the backend is running on port 8000 and reachable from your browser. A network failure can display clearly labeled offline sample data.</li>
          <li><strong>Scan timeout:</strong> try a smaller repository or upload. The browser scan timeout is five minutes.</li>
          <li><strong>Docker unavailable:</strong> start Docker on the backend server or upload a .tar export instead.</li>
          <li><strong>Semgrep not found:</strong> install backend requirements and ensure the Semgrep executable is available to the backend process.</li>
          <li><strong>Authentication or history unavailable:</strong> configure VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY and create the scan_history table with per-user access policies as described in src/supabase.js.</li>
        </ul>
      </section>
      <section id="api" className="info-card">
        <h2>API reference</h2>
        <p>The backend exposes these endpoints:</p>
        <ul>
          <li><code>POST /scan</code> — JSON with target_directory (server-local path or Git URL).</li>
          <li><code>POST /scan/upload</code> — ZIP upload in the multipart file field.</li>
          <li><code>POST /scan/binary</code> — binary upload in the multipart file field.</li>
          <li><code>POST /scan/container/upload</code> — container .tar upload in the multipart file field.</li>
          <li><code>POST /scan/container</code> — JSON with image_tag.</li>
          <li><code>GET /health</code> and <code>GET /health/docker</code> — service availability.</li>
        </ul>
        <a href={`http://${window.location.hostname}:8000/docs`} target="_blank" rel="noreferrer">Open interactive API reference <ExternalLink size={14} /></a>
        <a href="https://csrc.nist.gov/projects/post-quantum-cryptography" target="_blank" rel="noreferrer">NIST post-quantum cryptography <ExternalLink size={14} /></a>
      </section>
    </article>
  )
}
