export interface Partner {
  slug: string;
  display_name: string;
  notes: string;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(`/api/admin${path}`, {
    ...options,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(options?.headers || {}) },
  });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new Error(body.error || `Request failed: ${resp.status}`);
  }
  return resp.json();
}

export const api = {
  login: (secret: string) =>
    request<{ ok: boolean }>("/login", { method: "POST", body: JSON.stringify({ secret }) }),
  listPartners: () => request<{ partners: Partner[] }>("/partners"),
  getPartner: (slug: string) => request<Partner>(`/partners/${slug}`),
  createPartner: (display_name: string, notes: string) =>
    request<{ partner: Partner; raw_key: string; note: string }>("/partners", {
      method: "POST",
      body: JSON.stringify({ display_name, notes }),
    }),
  updatePartner: (slug: string, body: Omit<Partner, "slug">) =>
    request<Partner>(`/partners/${slug}`, { method: "POST", body: JSON.stringify(body) }),
};
