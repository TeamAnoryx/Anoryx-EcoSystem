"use server";

import { revalidatePath } from "next/cache";

import { adminApi } from "@/lib/admin-client";
import { AdminApiError } from "@/lib/errors";
import type {
  SprintCreateRequest,
  SprintStatusUpdateRequest,
  SprintView,
  TaskCreateRequest,
  TaskDependencyCreateRequest,
  TaskDependencyView,
  TaskStatusUpdateRequest,
  TaskView,
} from "@/lib/types";

/** Server Actions for the D-015 PM UI. Mirrors erp/actions.ts's discriminated-result
 * shape exactly — `adminApi` is `server-only`, so DELTA_ADMIN_TOKEN never reaches the
 * browser either way. */
export type ActionResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; detail?: string; message: string };

function fromError(err: unknown, fallback: string): ActionResult<never> {
  if (err instanceof AdminApiError) {
    return { ok: false, status: err.status, detail: err.detail, message: err.detail ?? fallback };
  }
  return { ok: false, status: 500, message: fallback };
}

export async function createSprintAction(
  input: SprintCreateRequest,
): Promise<ActionResult<SprintView>> {
  try {
    const sprint = await adminApi.createSprint(input);
    revalidatePath("/pm");
    return { ok: true, data: sprint };
  } catch (err) {
    return fromError(err, "Could not create the sprint.");
  }
}

export async function updateSprintStatusAction(
  sprintId: string,
  input: SprintStatusUpdateRequest,
): Promise<ActionResult<SprintView>> {
  try {
    const sprint = await adminApi.updateSprintStatus(sprintId, input);
    revalidatePath("/pm");
    return { ok: true, data: sprint };
  } catch (err) {
    return fromError(err, "Could not update the sprint status.");
  }
}

export async function createTaskAction(
  input: TaskCreateRequest,
): Promise<ActionResult<TaskView>> {
  try {
    const task = await adminApi.createTask(input);
    revalidatePath("/pm");
    return { ok: true, data: task };
  } catch (err) {
    if (err instanceof AdminApiError && err.status === 404) {
      return { ok: false, status: 404, message: "That sprint no longer exists." };
    }
    return fromError(err, "Could not create the task.");
  }
}

export async function updateTaskStatusAction(
  taskId: string,
  input: TaskStatusUpdateRequest,
): Promise<ActionResult<TaskView>> {
  try {
    const task = await adminApi.updateTaskStatus(taskId, input);
    revalidatePath("/pm");
    return { ok: true, data: task };
  } catch (err) {
    return fromError(err, "Could not update the task status.");
  }
}

export async function createDependencyAction(
  input: TaskDependencyCreateRequest,
): Promise<ActionResult<TaskDependencyView>> {
  try {
    const dependency = await adminApi.createDependency(input);
    revalidatePath("/pm");
    return { ok: true, data: dependency };
  } catch (err) {
    if (err instanceof AdminApiError && err.status === 422) {
      return {
        ok: false,
        status: 422,
        message:
          err.detail === "task_cannot_block_itself"
            ? "A task cannot block itself."
            : "That dependency would create a cycle.",
      };
    }
    if (err instanceof AdminApiError && err.status === 404) {
      return { ok: false, status: 404, message: "One of those tasks no longer exists." };
    }
    return fromError(err, "Could not create the dependency.");
  }
}
