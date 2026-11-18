import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

export default function PartnerNew() {
  const [displayName, setDisplayName] = useState("");
  const [notes, setNotes] = useState("");
  const [result, setResult] = useState<{ raw_key: string; slug: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const r = await api.createPartner(displayName, notes);
      setResult({ raw_key: r.raw_key, slug: r.partner.slug });
    } catch {
      navigate("/admin/login");
    }
  }

  if (result) {
    return (
      <div className="page narrow">
        <h1>Partner Created</h1>
        <p>
          Created <strong>{displayName}</strong> (slug: <code>{result.slug}</code>).
        </p>
        <p>
          <strong>Raw API key (shown once — copy it now, it is not recoverable again):</strong>
        </p>
        <pre className="key">{result.raw_key}</pre>
        <p className="muted">
          To actually gate <code>/api/tx</code> with this key, add it to{" "}
          <code>ENTROPA_API_KEYS</code> and redeploy — this panel doesn't do that automatically
          yet.
        </p>
        <p>
          <a href="/admin">← Back to partners</a>
        </p>
      </div>
    );
  }

  return (
    <div className="page narrow">
      <h1>New Partner</h1>
      <form onSubmit={submit}>
        <label>
          Display name
          <input
            required
            autoFocus
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </label>
        <label>
          Notes
          <textarea value={notes} onChange={(e) => setNotes(e.target.value)} />
        </label>
        {error && <p className="error">{error}</p>}
        <button type="submit">Create &amp; generate key</button>
      </form>
    </div>
  );
}
