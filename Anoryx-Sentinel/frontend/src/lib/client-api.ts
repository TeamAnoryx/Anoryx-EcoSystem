/**
 * Client-side typed helpers for admin mutations (ADR-0015 D8). These call the
 * BFF route (`/api/admin/*`) — never Sentinel directly — so the token stays
 * server-side (R1/R2). No untyped fetch leaks into components.
 *
 * NOT `server-only`: this is the one fetch path used by client components.
 */

export class ClientApiError extends Error {
  readonly status: number;
  readonly reauth: boolean;
  constructor(status: number, message: string, reauth = false) {
    super(message);
    this.name = "ClientApiError";
    this.status = status;
    this.reauth = reauth;
  }
}

async function call<T>(method: "POST" | "PATCH", path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api/admin/${path}`, {
      method,
      headers: body !== undefined ? { "Content-Type": "application/json" } : {},
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ClientApiError(502, "Could not reach the server.");
  }
  const data = (await res.json().catch(() => null)) as
    | (T & { error?: string; reauth?: boolean })
    | null;
  if (!res.ok) {
    throw new ClientApiError(res.status, data?.error ?? "Request failed.", Boolean(data?.reauth));
  }
  return data as T;
}

export const clientApi = {
  post: <T>(path: string, body?: unknown) => call<T>("POST", path, body),
  patch: <T>(path: string, body?: unknown) => call<T>("PATCH", path, body),
};
