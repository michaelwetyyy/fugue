import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import TaskResultPanel from "./TaskResultPanel";
import type { TaskResult } from "./submission";

const task = {
  input: {
    submission_id: "123e4567-e89b-12d3-a456-426614174000",
    lane: "homelab",
    repository: "/Users/example/project",
    scope: ["src/main.ts"],
    objective: "Review the boundary",
    agent_lifecycle: "persistent" as const,
    reservation_attempt: 1,
  },
  submission: {
    submission_id: "123e4567-e89b-12d3-a456-426614174000",
    work_id: "work-one",
    lane: "homelab",
    state: "accepted" as const,
    agent_lifecycle: "persistent" as const,
    child_agents: "allowed" as const,
    reservation_attempt: 1,
  },
};

const completed: TaskResult = {
  submission_id: task.input.submission_id,
  reservation_attempt: 1,
  state: "completed",
  outcome: "succeeded",
  result_ref: "result-one",
  text: "Done",
  persistent_session_state: "active",
};

describe("persistent task result lifecycle", () => {
  it("requires an explicit second action before deleting a retained session", async () => {
    const user = userEvent.setup();
    const closeSession = vi.fn().mockResolvedValue({
      submission_id: task.input.submission_id,
      reservation_attempt: 1,
      state: "closed",
      reason: null,
    });
    render(<TaskResultPanel
      task={task}
      onClose={() => {}}
      onFollowup={() => {}}
      read={async () => completed}
      closeSession={closeSession}
    />);

    await user.click(screen.getByRole("button", { name: "Check result" }));
    expect(await screen.findByText("Done")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close retained session" }));
    expect(closeSession).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Confirm close" }));
    expect(closeSession).toHaveBeenCalledWith(task.input.submission_id, 1);
    expect(await screen.findByText("RETAINED SESSION CLOSED")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Continue task/ })).not.toBeInTheDocument();
  });

  it("fences an uncertain close instead of offering continuation or blind retry", async () => {
    const user = userEvent.setup();
    render(<TaskResultPanel
      task={task}
      onClose={() => {}}
      onFollowup={() => {}}
      read={async () => completed}
      closeSession={async () => ({
        submission_id: task.input.submission_id,
        reservation_attempt: 1,
        state: "attention",
        reason: "persistent_session_attention",
      })}
    />);

    await user.click(screen.getByRole("button", { name: "Check result" }));
    await user.click(screen.getByRole("button", { name: "Close retained session" }));
    await user.click(screen.getByRole("button", { name: "Confirm close" }));
    expect(await screen.findByText(/SESSION FENCED/)).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(/will not be reused/i);
    expect(screen.queryByRole("button", { name: /Continue task/ })).not.toBeInTheDocument();
  });
});
