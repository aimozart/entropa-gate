import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, Partner } from "../api";

export default function PartnerList() {
  const [partners, setPartners] = useState<Partner[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    api
      .listPartners()
      .then((r) => setPartners(r.partners))
      .catch(() => navigate("/admin/login"));
  }, [navigate]);

  return (
    <div className="page">
      <h1>Partners</h1>
      <p>
        <Link to="/admin/new">+ New partner</Link>
      </p>
      {error && <p className="error">{error}</p>}
      {partners === null ? (
        <p>Loading…</p>
      ) : partners.length === 0 ? (
        <p className="muted">No partners yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Slug</th>
            </tr>
          </thead>
          <tbody>
            {partners.map((p) => (
              <tr key={p.slug}>
                <td>
                  <Link to={`/admin/${p.slug}`}>{p.display_name}</Link>
                </td>
                <td>{p.slug}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
