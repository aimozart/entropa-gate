import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api, Partner } from "../api";

export default function PartnerDetail() {
  const { slug } = useParams<{ slug: string }>();
  const [partner, setPartner] = useState<Partner | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (!slug) return;
    api
      .getPartner(slug)
      .then(setPartner)
      .catch(() => navigate("/admin/login"));
  }, [slug, navigate]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!partner || !slug) return;
    setSaved(false);
    setError(null);
    try {
      const updated = await api.updatePartner(slug, {
        display_name: partner.display_name,
        notes: partner.notes,
      });
      setPartner(updated);
      setSaved(true);
    } catch {
      setError("Failed to save.");
    }
  }

  if (!partner) return <div className="page narrow"><p>Loading…</p></div>;

  return (
    <div className="page narrow">
      <h1>Edit {partner.display_name}</h1>
      <form onSubmit={submit}>
        <label>
          Display name
          <input
            required
            value={partner.display_name}
            onChange={(e) => setPartner({ ...partner, display_name: e.target.value })}
          />
        </label>
        <label>
          Notes
          <textarea
            value={partner.notes}
            onChange={(e) => setPartner({ ...partner, notes: e.target.value })}
          />
        </label>
        {saved && <p className="success">Saved.</p>}
        {error && <p className="error">{error}</p>}
        <button type="submit">Save</button>
      </form>
      <p>
        <a href="/admin">← Back to partners</a>
      </p>
    </div>
  );
}
