import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

export default function Login() {
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.login(secret);
      navigate("/admin");
    } catch {
      setError("Wrong secret.");
    }
  }

  return (
    <div className="page narrow">
      <h1>Entropa Admin</h1>
      <form onSubmit={submit}>
        <label>
          Admin secret
          <input
            type="password"
            autoFocus
            required
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
          />
        </label>
        {error && <p className="error">{error}</p>}
        <button type="submit">Log in</button>
      </form>
    </div>
  );
}
