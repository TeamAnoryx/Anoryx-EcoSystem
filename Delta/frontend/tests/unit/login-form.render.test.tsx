/**
 * Login form — RENDERED-DOM assertion test (mirrors Anoryx-Sentinel/frontend's
 * shadow-ai-feed.render.test.tsx pattern: render the actual component in a
 * jsdom environment and assert against the DOM nodes that land in the
 * browser).
 *
 * Covers:
 *  - The token input is present, masked (type=password), and unlabeled with
 *    the literal env var name (defense-in-depth: nothing resembling the
 *    secret's identity should be visible chrome).
 *  - The submit button is disabled until a token is entered (basic UX guard
 *    against an accidental empty submit).
 *  - The rendered HTML never contains the literal admin token env var name.
 */

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const replace = vi.fn();
const refresh = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace, refresh }),
}));

import { LoginForm } from "@/components/login-form";

describe("LoginForm — rendered DOM assertions", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("renders a masked (type=password) token input", () => {
    render(<LoginForm />);
    const input = screen.getByLabelText("Admin token");
    expect(input).toBeInTheDocument();
    expect(input).toHaveAttribute("type", "password");
    expect(input).toHaveAttribute("autoComplete", "off");
  });

  it("renders a submit button, disabled until a token is entered", () => {
    render(<LoginForm />);
    const button = screen.getByRole("button", { name: /sign in/i });
    expect(button).toBeInTheDocument();
    expect(button).toBeDisabled();
  });

  it("never renders the literal DELTA_ADMIN_TOKEN env var name in the DOM", () => {
    const { container } = render(<LoginForm />);
    expect(container.textContent ?? "").not.toContain("DELTA_ADMIN_TOKEN");
  });

  it("renders exactly one form with a single text-entry token field", () => {
    const { container } = render(<LoginForm />);
    const forms = container.querySelectorAll("form");
    expect(forms).toHaveLength(1);
    expect(container.querySelectorAll("input[type='password']")).toHaveLength(1);
  });
});
