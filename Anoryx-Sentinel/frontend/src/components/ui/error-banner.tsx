/** Operator-friendly error banner (vector 9 — never a raw stack). */
export function ErrorBanner({ message }: { message: string }) {
  return (
    <div role="alert" className="rounded-md border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger">
      {message}
    </div>
  );
}
