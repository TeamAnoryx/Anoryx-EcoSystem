"use server";

import { revalidatePath } from "next/cache";

import { adminApi } from "@/lib/admin-client";
import { AdminApiError } from "@/lib/errors";
import type {
  TaskAssignmentView,
  TaskTeamAssignRequest,
  TeamCapacityUpdateRequest,
  TeamCreateRequest,
  TeamView,
} from "@/lib/types";

/** Server Actions for the D-016 team-capacity UI. Mirrors pm/actions.ts's
 * discriminated-result shape exactly — `adminApi` is `server-only`, so
 * DELTA_ADMIN_TOKEN never reaches the browser either way. */
export type ActionResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; detail?: string; message: string };

function fromError(err: unknown, fallback: string): ActionResult<never> {
  if (err instanceof AdminApiError) {
    return { ok: false, status: err.status, detail: err.detail, message: err.detail ?? fallback };
  }
  return { ok: false, status: 500, message: fallback };
}

export async function createTeamAction(
  input: TeamCreateRequest,
): Promise<ActionResult<TeamView>> {
  try {
    const team = await adminApi.createTeam(input);
    revalidatePath("/capacity");
    return { ok: true, data: team };
  } catch (err) {
    return fromError(err, "Could not create the team.");
  }
}

export async function updateTeamCapacityAction(
  teamId: string,
  input: TeamCapacityUpdateRequest,
): Promise<ActionResult<TeamView>> {
  try {
    const team = await adminApi.updateTeamCapacity(teamId, input);
    revalidatePath("/capacity");
    return { ok: true, data: team };
  } catch (err) {
    return fromError(err, "Could not update the team's capacity.");
  }
}

export async function assignTaskTeamAction(
  taskId: string,
  input: TaskTeamAssignRequest,
): Promise<ActionResult<TaskAssignmentView>> {
  try {
    const assignment = await adminApi.assignTaskTeam(taskId, input);
    revalidatePath("/capacity");
    return { ok: true, data: assignment };
  } catch (err) {
    if (err instanceof AdminApiError && err.status === 404) {
      return {
        ok: false,
        status: 404,
        message: err.detail === "team_not_found" ? "That team no longer exists." : "That task no longer exists.",
      };
    }
    return fromError(err, "Could not assign the task to that team.");
  }
}
