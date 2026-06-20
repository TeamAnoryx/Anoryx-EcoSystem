"use client";

import { CopyButton } from "@/components/ui/copy-button";
import { Modal } from "@/components/ui/modal";

/**
 * One-time secret reveal (R5, vector 6). The plaintext key is shown exactly once,
 * here, immediately after mint/rotate. It is never re-fetchable and is held only
 * in this component's props for the modal's lifetime — never persisted.
 */
export function SecretReveal({ secret, onClose }: { secret: string; onClose: () => void }) {
  return (
    <Modal title="Copy this key now" onClose={onClose} closeLabel="Done">
      <p className="text-sm text-warn">
        This is the only time the secret will be shown. It cannot be retrieved again — copy and
        store it securely now.
      </p>
      <div className="mt-3 flex items-center gap-2 rounded-md border border-border bg-bg-inset p-3">
        <code className="flex-1 break-all font-mono text-sm text-fg">{secret}</code>
        <CopyButton value={secret} />
      </div>
    </Modal>
  );
}
