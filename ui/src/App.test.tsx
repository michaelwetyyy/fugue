import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App, { activityAgentIsRecent } from "./App";
import { DEFAULT_TOPOLOGY_SETTINGS } from "./SettingsPage";
import { snapshotFixture } from "./test/fixture";
import { SourceInboxUnsupportedError } from "./source";

const storedPreferences = new Map<string, string>();
const localStorageDouble = {
  clear: () => storedPreferences.clear(),
  getItem: (key: string) => storedPreferences.get(key) ?? null,
  key: (index: number) => [...storedPreferences.keys()][index] ?? null,
  get length() { return storedPreferences.size; },
  removeItem: (key: string) => { storedPreferences.delete(key); },
  setItem: (key: string, value: string) => { storedPreferences.set(key, value); },
};

const integrationStatus = (armed = true) => ({
  armed,
  ready: armed,
  trust_mode: "secure" as const,
  backend_ready: armed,
  notifier_ready: armed,
  codex_cli: true,
  pending_callbacks: 0,
  queued_dispatches: 0,
});

const llmStatus = (model = "provider/model-a", effort = "low") => ({
  available: true,
  supported_models: ["provider/model-a", "provider/model-b"],
  supported_efforts_by_model: {
    "provider/model-a": ["low", "high"],
    "provider/model-b": ["medium"],
  },
  current_model: model,
  current_effort: effort,
  effective_model: model,
  effective_effort: effort,
});

describe("Fugue offload cockpit", () => {
  beforeEach(() => {
    Object.defineProperty(window, "localStorage", { configurable: true, value: localStorageDouble });
    window.localStorage.clear();
  });

  it("renders a read-only topology from the validated snapshot", async () => {
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshotFixture()} />);

    expect(await screen.findByRole("heading", { name: "Agent graph" })).toBeInTheDocument();
    expect(screen.getByLabelText(/Interactive 3D Fugue agent graph/i)).toBeInTheDocument();
    expect(screen.getByText(/DRAG BACKGROUND TO ROTATE.*DRAG NODE TO MOVE/)).toBeInTheDocument();
    expect(screen.getByText("OFFLOAD TOPOLOGY")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Work queue" })).toBeInTheDocument();
    expect(screen.getByText("Persistent")).toBeInTheDocument();
    expect(screen.getAllByText(/PERSISTENT/).length).toBeGreaterThan(0);
    expect(document.querySelector(".graph-summary")?.textContent).toContain("1 ACTION");
    expect(document.querySelector(".graph-summary")?.textContent).toContain("1 DELIVERY");
    expect(await screen.findByText(/1 needs attention · 1 delivery notice/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /new task/i })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Objective")).not.toBeInTheDocument();
  });

  it("collapses, restores and keyboard-resizes the inspector", async () => {
    const user = userEvent.setup();
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshotFixture()} />);
    await screen.findByRole("heading", { name: "Agent graph" });

    const resize = screen.getByRole("separator", { name: "Resize inspector" });
    expect(resize).toHaveAttribute("aria-valuenow", "360");
    resize.focus();
    await user.keyboard("{ArrowLeft}");
    expect(screen.getByRole("separator", { name: "Resize inspector" })).toHaveAttribute("aria-valuenow", "384");
    expect(window.localStorage.getItem("fugue.inspector.width.v1")).toBe("384");

    await user.click(screen.getByRole("button", { name: "COLLAPSE" }));
    expect(screen.getByRole("button", { name: "Expand inspector" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Expand inspector" }));
    expect(screen.getByRole("separator", { name: "Resize inspector" })).toHaveAttribute("aria-valuenow", "384");
  });

  it("filters route types and opens an exact worker transcript", async () => {
    const user = userEvent.setup();
    const loadTranscript = vi.fn().mockResolvedValue({
      thread_id: "session-tensorhost-1",
      slot_id: "tensorhost-1",
      work_id: "work-42",
      generation: 1,
      fetched_at: "2026-09-06T11:00:00Z",
      expires_at: "2026-09-06T11:05:00Z",
      turns: [{ seq: 0, role: "agent", kind: "text", preview: "bounded result", state: "committed" }],
      redacted: ["messages[0].parts[1]"],
      anchor_item_id: "message-root",
    });
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshotFixture()} loadTranscript={loadTranscript} />);
    await screen.findByRole("heading", { name: "Agent graph" });

    const callbacks = screen.getByRole("button", { name: "CALLBACKS" });
    await user.click(callbacks);
    expect(callbacks).toHaveAttribute("aria-pressed", "true");

    await user.click(screen.getByRole("button", { name: /TENSORHOST-1 PERSISTENT/i }));
    expect(screen.getByRole("complementary", { name: "tensorhost-1 details" })).toBeInTheDocument();
    expect(await screen.findByText("bounded result")).toBeInTheDocument();
    expect(loadTranscript).toHaveBeenCalledWith({ slot_id: "tensorhost-1", work_id: "work-42", generation: 1 });
    expect(screen.getByText(/Transcript held in memory only/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Refresh transcript" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "ROUTES" }));
    expect(screen.getByText("transport-42")).toBeInTheDocument();
  });

  it("refreshes Codex source status from App Server notifications without duplicating the watcher", async () => {
    const user = userEvent.setup();
    let releaseChange!: (value: { method: "turn/started" }) => void;
    const firstChange = new Promise<{ method: "turn/started" }>((resolve) => { releaseChange = resolve; });
    const never = new Promise<{ method: "turn/completed" }>(() => {});
    const watchSourceChanges = vi.fn()
      .mockImplementationOnce(() => firstChange)
      .mockImplementation(() => never);
    const idle = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "idle" as const, activeFlags: [] };
    const active = { ...idle, updatedAt: 3, runtimeStatus: "active" as const, activeFlags: ["waiting"] };
    const loadSourceThreads = vi.fn()
      .mockResolvedValueOnce([idle])
      .mockResolvedValue([active]);
    const loadSnapshot = vi.fn().mockResolvedValue(snapshotFixture());

    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={loadSnapshot}
      loadSourceThreads={loadSourceThreads}
      watchSourceChanges={watchSourceChanges}
    />);
    await screen.findByRole("button", { name: /Source task IDLE · appServer/i });
    expect(loadSnapshot).toHaveBeenCalledOnce();
    expect(watchSourceChanges).toHaveBeenCalledOnce();

    await user.click(screen.getByRole("button", { name: "Refresh snapshot" }));
    await waitFor(() => expect(loadSnapshot).toHaveBeenCalledTimes(2));
    expect(watchSourceChanges).toHaveBeenCalledOnce();

    releaseChange({ method: "turn/started" });

    expect(await screen.findByRole("button", { name: /Source task ACTIVE · appServer/i })).toBeInTheDocument();
    expect(loadSourceThreads).toHaveBeenCalledTimes(3);
    expect(loadSnapshot).toHaveBeenCalledTimes(2);
    await waitFor(() => expect(watchSourceChanges).toHaveBeenCalledTimes(2));
  });

  it("reloads the selected per-thread inbox after every accepted source-change notification", async () => {
    const user = userEvent.setup();
    let releaseChange!: (value: { method: "thread/status/changed" }) => void;
    const firstChange = new Promise<{ method: "thread/status/changed" }>((resolve) => { releaseChange = resolve; });
    const never = new Promise<{ method: "turn/completed" }>(() => {});
    let sourceWatchCalls = 0;
    const watchSourceChanges = async () => {
      sourceWatchCalls += 1;
      return sourceWatchCalls === 1 ? await firstChange : await never;
    };
    const idle = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "idle" as const, activeFlags: [] };
    const loadSourceThreads = async () => [idle];
    let inboxLoads = 0;
    const loadSourceInbox = async () => {
      inboxLoads += 1;
      return inboxLoads === 1 ? {
        status: "available" as const, source_id: "thread-1", runtime_status: "idle" as const, active_turn_id: null,
        items: [], total: 0, total_status: "exact" as const, lower_bound: 0, truncated: false,
      } : {
        status: "available" as const, source_id: "thread-1", runtime_status: "active" as const, active_turn_id: "turn-1",
        items: [], total: 0, total_status: "exact" as const, lower_bound: 0, truncated: false,
      };
    };
    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={async () => snapshotFixture()}
      loadSourceThreads={loadSourceThreads}
      loadSourceInbox={loadSourceInbox}
      watchSourceChanges={watchSourceChanges}
      inspectSource={async () => ({ threadId: "thread-1", activeTurnId: null, turns: [] })}
    />);
    await screen.findByRole("button", { name: /Source task IDLE · appServer/i });
    await waitFor(() => expect(sourceWatchCalls).toBe(1));
    await user.click(screen.getByRole("button", { name: /Source task IDLE · appServer/i }));
    const inspector = await screen.findByRole("complementary", { name: "Source task source thread" });
    await waitFor(() => expect(inspector).toHaveTextContent(/RuntimeIDLE/i));
    expect(inboxLoads).toBe(1);

    releaseChange({ method: "thread/status/changed" });

    await waitFor(() => expect(inboxLoads).toBe(2));
    await waitFor(() => expect(inspector).toHaveTextContent(/RuntimeACTIVE/i));
  });

  it("coalesces source-change bursts to one dirty selected-inbox refresh", async () => {
    const user = userEvent.setup();
    const releases: Array<(value: { method: "thread/status/changed" }) => void> = [];
    const watchSourceChanges = vi.fn(() => new Promise<{ method: "thread/status/changed" }>((resolve) => { releases.push(resolve); }));
    const thread = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "idle" as const, activeFlags: [] };
    const idleInbox = {
      status: "available" as const, source_id: "thread-1", runtime_status: "idle" as const, active_turn_id: null,
      items: [], total: 0, total_status: "exact" as const, lower_bound: 0, truncated: false,
    };
    const activeInbox = { ...idleInbox, runtime_status: "active" as const, active_turn_id: "turn-1" };
    let resolvePending!: (value: typeof activeInbox) => void;
    const pending = new Promise<typeof activeInbox>((resolve) => { resolvePending = resolve; });
    const loadSourceInbox = vi.fn()
      .mockResolvedValueOnce(idleInbox)
      .mockImplementationOnce(() => pending)
      .mockResolvedValue(activeInbox);

    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={async () => snapshotFixture()}
      loadSourceThreads={async () => [thread]}
      loadSourceInbox={loadSourceInbox}
      watchSourceChanges={watchSourceChanges}
      inspectSource={async () => ({ threadId: "thread-1", activeTurnId: null, turns: [] })}
    />);
    await waitFor(() => expect(releases.length).toBe(1));
    await user.click(await screen.findByRole("button", { name: /Source task IDLE · appServer/i }));
    await waitFor(() => expect(loadSourceInbox).toHaveBeenCalledTimes(1));

    releases[0]({ method: "thread/status/changed" });
    await waitFor(() => expect(loadSourceInbox).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(releases.length).toBe(2));

    releases[1]({ method: "thread/status/changed" });
    await waitFor(() => expect(releases.length).toBe(3));
    releases[2]({ method: "thread/status/changed" });
    await waitFor(() => expect(releases.length).toBe(4));
    expect(loadSourceInbox).toHaveBeenCalledTimes(2);

    resolvePending(activeInbox);
    await waitFor(() => expect(loadSourceInbox).toHaveBeenCalledTimes(3));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(loadSourceInbox).toHaveBeenCalledTimes(3);
  });

  it("re-arms a failed Codex source watcher only after manual refresh", async () => {
    const user = userEvent.setup();
    const never = new Promise<{ method: "turn/completed" }>(() => {});
    const watchSourceChanges = vi.fn()
      .mockRejectedValueOnce(new Error("source unavailable"))
      .mockImplementation(() => never);
    const thread = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "idle" as const, activeFlags: [] };
    const loadSourceThreads = vi.fn().mockResolvedValue([thread]);
    const loadSnapshot = vi.fn().mockResolvedValue(snapshotFixture());

    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={loadSnapshot}
      loadSourceThreads={loadSourceThreads}
      watchSourceChanges={watchSourceChanges}
    />);
    await screen.findByRole("button", { name: /Source task IDLE · appServer/i });
    await waitFor(() => expect(watchSourceChanges).toHaveBeenCalledOnce());

    await user.click(screen.getByRole("button", { name: "Refresh snapshot" }));

    await waitFor(() => expect(loadSnapshot).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(watchSourceChanges).toHaveBeenCalledTimes(2));
  });

  it("manual refresh retries the selected source inbox even when the event sequence is unchanged", async () => {
    const user = userEvent.setup();
    const thread = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "idle" as const, activeFlags: [] };
    const loadSnapshot = vi.fn().mockResolvedValue(snapshotFixture());
    const loadSourceInbox = vi.fn()
      .mockRejectedValueOnce(new Error("transient inbox failure"))
      .mockResolvedValue({
        status: "available" as const, source_id: "thread-1", runtime_status: "idle" as const, active_turn_id: null,
        items: [], total: 0, total_status: "exact" as const, lower_bound: 0, truncated: false,
      });

    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={loadSnapshot}
      loadSourceThreads={async () => [thread]}
      loadSourceInbox={loadSourceInbox}
      inspectSource={async () => ({ threadId: "thread-1", activeTurnId: null, turns: [] })}
    />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(await screen.findByRole("button", { name: /Source task IDLE · appServer/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Source inbox unavailable.*not being inferred/i);
    expect(loadSourceInbox).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "Refresh snapshot" }));

    await waitFor(() => expect(loadSnapshot).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(loadSourceInbox).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
    expect(screen.getByText("No source-bound messages are queued.")).toBeInTheDocument();
  });

  it("opens an exact Codex source thread and keeps its transcript in the inspector", async () => {
    const user = userEvent.setup();
    const thread = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "active" as const, activeFlags: [] };
    const snapshot = snapshotFixture();
    if (snapshot.source_inbox) snapshot.source_inbox.source_id = "thread-1";
    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={async () => snapshot}
      loadSourceThreads={async () => [thread]}
      loadSourceInbox={async () => { throw new SourceInboxUnsupportedError(); }}
      inspectSource={async () => ({ threadId: "thread-1", activeTurnId: "turn-1", turns: [{ id: "turn-1", status: "inProgress", lines: [{ role: "agent", text: "Working now" }] }] })}
    />);
    await screen.findByRole("heading", { name: "Agent graph" });

    await user.click(await screen.findByRole("button", { name: /Source task ACTIVE · appServer/i }));
    expect(screen.getByRole("complementary", { name: "Source task source thread" })).toBeInTheDocument();
    expect(await screen.findByText("Working now")).toBeInTheDocument();
    expect(screen.getByText("completion nudge · queued")).toBeInTheDocument();
    expect(screen.getByText(/exact active-turn steer/i)).toBeInTheDocument();
    expect(screen.getByText(/graph and logs remain metadata-only/i)).toBeInTheDocument();
  });

  it("refreshes the selected source inbox on committed controller events", async () => {
    const user = userEvent.setup();
    const thread = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "active" as const, activeFlags: [] };
    const first = snapshotFixture();
    const second = snapshotFixture();
    second.snapshot_version.event_sequence = (first.snapshot_version.event_sequence ?? 0) + 1;
    let releaseSnapshot!: (value: typeof second) => void;
    const watched = new Promise<typeof second>((resolve) => { releaseSnapshot = resolve; });
    const never = new Promise<typeof second>(() => {});
    const watchSnapshot = vi.fn().mockImplementationOnce(() => watched).mockImplementation(() => never);
    const loadSourceInbox = vi.fn().mockResolvedValue({
      status: "available" as const, source_id: "thread-1", runtime_status: "active" as const, active_turn_id: null,
      items: [], total: 0, total_status: "exact" as const, lower_bound: 0, truncated: false,
    });
    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={async () => first}
      watchSnapshot={watchSnapshot}
      loadSourceThreads={async () => [thread]}
      loadSourceInbox={loadSourceInbox}
      inspectSource={async () => ({ threadId: "thread-1", activeTurnId: null, turns: [] })}
    />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(await screen.findByRole("button", { name: /Source task ACTIVE · appServer/i }));
    await waitFor(() => expect(loadSourceInbox).toHaveBeenCalledTimes(1));

    releaseSnapshot(second);

    await waitFor(() => expect(loadSourceInbox).toHaveBeenCalledTimes(2));
    expect(loadSourceInbox).toHaveBeenNthCalledWith(1, "thread-1");
    expect(loadSourceInbox).toHaveBeenNthCalledWith(2, "thread-1");
    expect(watchSnapshot).toHaveBeenCalledWith(first.snapshot_version.event_sequence);
  });

  it("loads the exact selected source inbox and ignores a stale prior-thread result", async () => {
    const user = userEvent.setup();
    const threadA = { id: "thread-a", name: "Source A", cwd: "/repo/a", source: "appServer", createdAt: 1, updatedAt: 3, runtimeStatus: "active" as const, activeFlags: [] };
    const threadB = { id: "thread-b", name: "Source B", cwd: "/repo/b", source: "appServer", createdAt: 2, updatedAt: 4, runtimeStatus: "active" as const, activeFlags: [] };
    const inboxFor = (sourceId: string, origin: string) => ({
      status: "available" as const, source_id: sourceId, runtime_status: "active" as const, active_turn_id: null,
      items: [{ id: `callback-${sourceId}`, kind: "completion_nudge" as const, origin, work_id: `work-${sourceId}`, state: "accepted" as const, queued_at: "2026-09-10T20:00:00Z", reason: null }],
      total: 1, total_status: "exact" as const, lower_bound: 1, truncated: false,
    });
    let resolveA!: (value: ReturnType<typeof inboxFor>) => void;
    const pendingA = new Promise<ReturnType<typeof inboxFor>>((resolve) => { resolveA = resolve; });
    const loadSourceInbox = vi.fn((threadId: string) => threadId === "thread-a" ? pendingA : Promise.resolve(inboxFor(threadId, "control-b")));
    const snapshot = snapshotFixture();
    delete snapshot.source_inbox;
    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={async () => snapshot}
      loadSourceThreads={async () => [threadA, threadB]}
      loadSourceInbox={loadSourceInbox}
      inspectSource={async (threadId) => ({ threadId, activeTurnId: null, turns: [] })}
    />);
    await screen.findByRole("heading", { name: "Agent graph" });

    await user.click(await screen.findByRole("button", { name: /Source A ACTIVE · appServer/i }));
    await waitFor(() => expect(loadSourceInbox).toHaveBeenCalledWith("thread-a"));
    await user.click(await screen.findByRole("button", { name: /Source B ACTIVE · appServer/i }));
    expect(await screen.findByText(/control-b/)).toBeInTheDocument();
    expect(screen.getByText("completion nudge · accepted")).toBeInTheDocument();

    resolveA(inboxFor("thread-a", "control-a"));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(screen.getByText(/control-b/)).toBeInTheDocument();
    expect(screen.queryByText(/control-a/)).not.toBeInTheDocument();
    expect(loadSourceInbox).toHaveBeenCalledWith("thread-b");
  });

  it("revokes stale transcript and send authority immediately when the selected thread changes", async () => {
    const user = userEvent.setup();
    const threadA = { id: "thread-a", name: "Source A", cwd: "/repo/a", source: "appServer", createdAt: 1, updatedAt: 3, runtimeStatus: "active" as const, activeFlags: [] };
    const threadB = { id: "thread-b", name: "Source B", cwd: "/repo/b", source: "appServer", createdAt: 2, updatedAt: 4, runtimeStatus: "active" as const, activeFlags: [] };
    const emptyInbox = (threadId: string) => ({
      status: "available" as const, source_id: threadId, runtime_status: "active" as const, active_turn_id: null,
      items: [], total: 0, total_status: "exact" as const, lower_bound: 0, truncated: false,
    });
    let resolveB!: (value: { threadId: string; activeTurnId: string | null; turns: Array<{ id: string; status: string; lines: Array<{ role: "agent"; text: string }> }> }) => void;
    const pendingB = new Promise<Parameters<typeof resolveB>[0]>((resolve) => { resolveB = resolve; });
    const inspectSource = vi.fn((threadId: string) => threadId === "thread-a"
      ? Promise.resolve({ threadId, activeTurnId: "turn-a", turns: [{ id: "turn-a", status: "inProgress", lines: [{ role: "agent" as const, text: "A private transcript" }] }] })
      : pendingB);
    const composeSource = vi.fn().mockResolvedValue({ endpoint: "turn/steer", messageId: "message-b", routeId: null, state: "committed", turnId: "turn-b", reason: "committed", transitions: [] });
    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={async () => snapshotFixture()}
      loadSourceThreads={async () => [threadA, threadB]}
      loadSourceInbox={async (threadId) => emptyInbox(threadId)}
      inspectSource={inspectSource}
      composeSource={composeSource}
    />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(await screen.findByRole("button", { name: /Source A ACTIVE · appServer/i }));
    expect(await screen.findByText("A private transcript")).toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: "Message this Codex thread" }), "draft for A");

    await user.click(screen.getByRole("button", { name: /Source B ACTIVE · appServer/i }));
    expect(screen.queryByText("A private transcript")).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Message this Codex thread" })).not.toBeInTheDocument();
    expect(composeSource).not.toHaveBeenCalled();

    resolveB({ threadId: "thread-b", activeTurnId: "turn-b", turns: [{ id: "turn-b", status: "inProgress", lines: [{ role: "agent", text: "B transcript" }] }] });
    expect(await screen.findByText("B transcript")).toBeInTheDocument();
    const composer = screen.getByRole("textbox", { name: "Message this Codex thread" });
    expect(composer).toHaveValue("");
    await user.type(composer, "message for B");
    await user.click(screen.getByRole("button", { name: "SEND ONCE" }));
    await waitFor(() => expect(composeSource).toHaveBeenCalledOnce());
    expect(composeSource.mock.calls[0][0].threadId).toBe("thread-b");
    expect(composeSource.mock.calls[0][1]).toBe("message for B");
  });

  it("does not use a legacy snapshot inbox merely because the live loader is disabled", async () => {
    const user = userEvent.setup();
    const thread = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "active" as const, activeFlags: [] };
    const snapshot = snapshotFixture();
    if (snapshot.source_inbox) snapshot.source_inbox.source_id = "thread-1";
    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={async () => snapshot}
      loadSourceThreads={async () => [thread]}
      loadSourceInbox={null}
      inspectSource={async () => ({ threadId: "thread-1", activeTurnId: null, turns: [] })}
    />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(await screen.findByRole("button", { name: /Source task ACTIVE · appServer/i }));
    expect(await screen.findByText("Source inbox metadata is unavailable.")).toBeInTheDocument();
    expect(screen.queryByText("completion nudge · queued")).not.toBeInTheDocument();
  });

  it("never renders a failed live inbox as an authoritative empty queue", async () => {
    const user = userEvent.setup();
    const thread = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "active" as const, activeFlags: [] };
    const snapshot = snapshotFixture();
    if (snapshot.source_inbox) snapshot.source_inbox.source_id = "thread-1";
    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={async () => snapshot}
      loadSourceThreads={async () => [thread]}
      loadSourceInbox={async () => { throw new Error("integrity failure"); }}
      inspectSource={async () => ({ threadId: "thread-1", activeTurnId: null, turns: [] })}
    />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(await screen.findByRole("button", { name: /Source task ACTIVE · appServer/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Source inbox unavailable.*not being inferred/i);
    expect(screen.queryByText("No source-bound messages are queued.")).not.toBeInTheDocument();
    expect(screen.queryByText("completion nudge · queued")).not.toBeInTheDocument();
  });

  it("uses the legacy snapshot inbox only for a positively identified unsupported controller", async () => {
    const user = userEvent.setup();
    const thread = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "active" as const, activeFlags: [] };
    const snapshot = snapshotFixture();
    if (snapshot.source_inbox) snapshot.source_inbox.source_id = "thread-1";
    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={async () => snapshot}
      loadSourceThreads={async () => [thread]}
      loadSourceInbox={async () => { throw new SourceInboxUnsupportedError(); }}
      inspectSource={async () => ({ threadId: "thread-1", activeTurnId: null, turns: [] })}
    />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(await screen.findByRole("button", { name: /Source task ACTIVE · appServer/i }));
    expect(await screen.findByText("completion nudge · queued")).toBeInTheDocument();
    expect(screen.queryByText(/Source inbox unavailable.*not being inferred/i)).not.toBeInTheDocument();
  });

  it("never labels a non-exact legacy inbox as an authoritative empty queue", async () => {
    const user = userEvent.setup();
    const thread = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "active" as const, activeFlags: [] };
    const snapshot = snapshotFixture();
    if (!snapshot.source_inbox) throw new Error("fixture requires source inbox");
    snapshot.source_inbox.source_id = "thread-1";
    snapshot.source_inbox.items = [];
    snapshot.source_inbox.total = null;
    snapshot.source_inbox.total_status = "unknown";
    snapshot.source_inbox.lower_bound = 0;
    snapshot.source_inbox.truncated = false;
    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={async () => snapshot}
      loadSourceThreads={async () => [thread]}
      loadSourceInbox={async () => { throw new SourceInboxUnsupportedError(); }}
      inspectSource={async () => ({ threadId: "thread-1", activeTurnId: null, turns: [] })}
    />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(await screen.findByRole("button", { name: /Source task ACTIVE · appServer/i }));
    expect(await screen.findByText("Source inbox count is not exact.")).toBeInTheDocument();
    expect(screen.queryByText("No source-bound messages are queued.")).not.toBeInTheDocument();
  });

  it("treats an unavailable legacy inbox as unavailable rather than empty or authoritative", async () => {
    const user = userEvent.setup();
    const thread = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "active" as const, activeFlags: [] };
    const snapshot = snapshotFixture();
    if (!snapshot.source_inbox) throw new Error("fixture requires source inbox");
    snapshot.source_inbox.source_id = "thread-1";
    snapshot.source_inbox.status = "unavailable";
    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={async () => snapshot}
      loadSourceThreads={async () => [thread]}
      loadSourceInbox={async () => { throw new SourceInboxUnsupportedError(); }}
      inspectSource={async () => ({ threadId: "thread-1", activeTurnId: null, turns: [] })}
    />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(await screen.findByRole("button", { name: /Source task ACTIVE · appServer/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Source inbox unavailable.*not being inferred/i);
    expect(screen.queryByText("No source-bound messages are queued.")).not.toBeInTheDocument();
    expect(screen.queryByText("completion nudge · queued")).not.toBeInTheDocument();
  });

  it("renders the exact per-thread inbox runtime state over the broader thread-list status", async () => {
    const user = userEvent.setup();
    const thread = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "active" as const, activeFlags: [] };
    render(<App
      startLifecycle={async () => {}}
      loadSnapshot={async () => snapshotFixture()}
      loadSourceThreads={async () => [thread]}
      loadSourceInbox={async () => ({
        status: "available", source_id: "thread-1", runtime_status: "unavailable", active_turn_id: null,
        items: [], total: 0, total_status: "exact", lower_bound: 0, truncated: false,
      })}
      inspectSource={async () => ({ threadId: "thread-1", activeTurnId: null, turns: [] })}
    />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(await screen.findByRole("button", { name: /Source task ACTIVE · appServer/i }));
    const inspector = screen.getByRole("complementary", { name: "Source task source thread" });
    await waitFor(() => expect(inspector).toHaveTextContent(/RuntimeUNAVAILABLE/i));
  });

  it("sends once to the selected binding and does not retry uncertainty", async () => {
    const user = userEvent.setup();
    const bundle = {
      thread_id: "session-tensorhost-1",
      slot_id: "tensorhost-1",
      work_id: "work-42",
      generation: 1,
      fetched_at: "2026-09-06T11:00:00Z",
      expires_at: "2026-09-06T11:05:00Z",
      turns: [{ seq: 0, role: "agent" as const, kind: "text" as const, preview: "ready", state: "committed" as const }],
      redacted: [],
      anchor_item_id: "message-root",
    };
    const composeWorker = vi.fn().mockResolvedValue({
      thread_id: bundle.thread_id,
      slot_id: bundle.slot_id,
      work_id: bundle.work_id,
      generation: bundle.generation,
      item_id: "message-1",
      state: "uncertain",
      queued_at: "2026-09-06T11:00:01Z",
      reason: "request_deadline_exceeded",
    });
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshotFixture()} loadTranscript={async () => bundle} composeWorker={composeWorker} />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(screen.getByRole("button", { name: /TENSORHOST-1 PERSISTENT/i }));
    await user.type(await screen.findByRole("textbox", { name: "Message this agent" }), "Continue with the bounded task");
    await user.click(screen.getByRole("button", { name: "SEND ONCE" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/uncertain.*will not retry automatically/i);
    expect(composeWorker).toHaveBeenCalledOnce();
    expect(composeWorker).toHaveBeenCalledWith(bundle, "Continue with the bounded task");
  });

  it("steers one exact Codex turn and logs only endpoint metadata", async () => {
    const user = userEvent.setup();
    const thread = { id: "thread-1", name: "Source task", cwd: "/repo", source: "appServer", createdAt: 1, updatedAt: 2, runtimeStatus: "active" as const, activeFlags: [] };
    const inspection = { threadId: "thread-1", activeTurnId: "turn-1", turns: [{ id: "turn-1", status: "inProgress", lines: [] }] };
    const outcome = { endpoint: "turn/steer" as const, messageId: "message-1", routeId: null, state: "unknown" as const, turnId: null, reason: "outcome_uncertain", transitions: [] };
    const composeSource = vi.fn().mockResolvedValue(outcome);
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshotFixture()} loadSourceThreads={async () => [thread]} inspectSource={async () => inspection} composeSource={composeSource} />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(await screen.findByRole("button", { name: /Source task ACTIVE · appServer/i }));
    await user.type(await screen.findByRole("textbox", { name: "Message this Codex thread" }), "private composer text");
    await user.click(screen.getByRole("button", { name: "SEND ONCE" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/turn\/steer.*unknown.*will not retry automatically/i);
    expect(composeSource).toHaveBeenCalledOnce();
    expect(composeSource).toHaveBeenCalledWith(inspection, "private composer text");
    expect(screen.getByRole("log")).toHaveTextContent(/turn\/steer · unknown/i);
    expect(screen.getByRole("log")).not.toHaveTextContent("private composer text");
  });

  it("shows idle capacity without inventing a dispatch", async () => {
    const user = userEvent.setup();
    const snapshot = snapshotFixture();
    snapshot.worker_graph.workers = snapshot.worker_graph.workers.map((worker) => ({
      ...worker,
      slot_state: "clear",
      work_id: null,
      agent_lifecycle: null,
      assignment_id: null,
      transport: { ...worker.transport, id: null, state: "idle" },
    }));
    snapshot.worker_graph.edges = [];
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshot} />);

    await screen.findByRole("heading", { name: "Agent graph" });
    expect(screen.getAllByText("AVAILABLE · idle").length).toBeGreaterThan(0);
    expect(screen.queryByText("dispatch")).not.toBeInTheDocument();
    expect(screen.getByText("AVAILABLE CAPACITY")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /TENSORHOST-1 AVAILABLE/i }));
    expect(screen.getByText("NO ACTIVE CONVERSATION")).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Message this agent" })).not.toBeInTheDocument();
  });

  it("opens retained completion history read-only for an idle worker", async () => {
    const user = userEvent.setup();
    const snapshot = snapshotFixture();
    snapshot.worker_graph.workers = snapshot.worker_graph.workers.map((worker) => ({
      ...worker,
      slot_state: "clear",
      work_id: null,
      agent_lifecycle: null,
      assignment_id: null,
      transport: { ...worker.transport, id: null, state: "idle" },
    }));
    snapshot.worker_graph.edges = [];
    snapshot.transcript_archive = {
      status: "available",
      items: [
        {
          archive_id: "completion-result-new",
          slot_id: "tensorhost-1",
          work_id: "work-archived-new",
          generation: 2,
          outcome: "succeeded",
          captured_at_us: 1_788_000_000_000_000,
          turn_count: 1,
          redaction_count: 0,
        },
        {
          archive_id: "completion-result-old",
          slot_id: "tensorhost-1",
          work_id: "work-archived-old",
          generation: 1,
          outcome: "failed",
          captured_at_us: 1_787_000_000_000_000,
          turn_count: 1,
          redaction_count: 1,
        },
      ],
      total: 2,
      total_status: "exact",
      lower_bound: 2,
      truncated: false,
      content_included: false,
    };
    const loadArchivedTranscript = vi.fn().mockImplementation(async (target: { archive_id: string; slot_id: string; work_id: string; generation: number }) => ({
      ...target,
      thread_id: `session-${target.generation}`,
      captured_at: target.generation === 2 ? "2026-09-09T14:00:00Z" : "2026-09-08T14:00:00Z",
      outcome: target.generation === 2 ? "succeeded" : "failed",
      turns: [{ seq: 0, role: "agent", kind: "text", preview: target.generation === 2 ? "new archived result" : "old archived result", state: "committed" }],
      redacted: target.generation === 2 ? [] : ["messages[0].text"],
      read_only: true,
    }));
    const composeWorker = vi.fn();
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshot} loadArchivedTranscript={loadArchivedTranscript} composeWorker={composeWorker} />);

    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(screen.getByRole("button", { name: /TENSORHOST-1 AVAILABLE/i }));
    expect(await screen.findByText("new archived result")).toBeInTheDocument();
    expect(screen.getByText("ARCHIVED CONVERSATION")).toBeInTheDocument();
    expect(screen.getByText(/Sanitized completion snapshot · read only · composer disabled/)).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Message this agent" })).not.toBeInTheDocument();
    expect(composeWorker).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: /work-archived-old/i }));
    expect(await screen.findByText("old archived result")).toBeInTheDocument();
    expect(loadArchivedTranscript).toHaveBeenLastCalledWith({
      archive_id: "completion-result-old",
      slot_id: "tensorhost-1",
      work_id: "work-archived-old",
      generation: 1,
    });
    expect(screen.queryByRole("textbox", { name: "Message this agent" })).not.toBeInTheDocument();
  });

  it("shows disposable and persistent lifecycle identity on assigned agents", async () => {
    const snapshot = snapshotFixture();
    snapshot.worker_graph.workers[0].agent_lifecycle = "disposable";
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshot} />);

    await screen.findByRole("heading", { name: "Agent graph" });
    expect(screen.getAllByText(/DISPOSABLE/).length).toBeGreaterThan(0);
    expect(screen.getByText("disposable")).toBeInTheDocument();
  });

  it("keeps the cockpit usable for an explicitly degraded missing lifecycle", async () => {
    const snapshot = snapshotFixture();
    snapshot.worker_graph.workers[0].agent_lifecycle = null;
    snapshot.availability.status = "degraded";
    snapshot.availability.errors = ["worker_graph.workers[0].agent_lifecycle is missing for assigned work"];
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshot} />);

    expect(await screen.findByRole("heading", { name: "Agent graph" })).toBeInTheDocument();
    expect(screen.getByText(/agent lifecycle is missing for assigned work/i)).toBeInTheDocument();
    expect(screen.getAllByText(/METADATA PENDING/).length).toBeGreaterThan(0);
  });

  it("keeps every active agent reachable when more than five are assigned", async () => {
    const snapshot = snapshotFixture();
    snapshot.worker_graph.workers = snapshot.worker_graph.workers.map((worker, index) => ({
      ...worker,
      slot_state: "assigned",
      work_id: `work-${index}`,
      assignment_id: `assignment-${index}`,
      agent_lifecycle: index % 2 ? "disposable" : "persistent",
      transport: { ...worker.transport, state: "reserved" },
    }));
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshot} />);

    await screen.findByRole("heading", { name: "Agent graph" });
    expect(screen.getAllByRole("button", { name: /(PERSISTENT|DISPOSABLE) · work-/ })).toHaveLength(snapshot.worker_graph.workers.length);
  });

  it("shows an inert unavailable state and can retry", async () => {
    const user = userEvent.setup();
    const loader = vi.fn().mockRejectedValueOnce(new Error("controller_unavailable")).mockResolvedValueOnce(snapshotFixture());
    render(<App startLifecycle={async () => {}} loadSnapshot={loader} />);

    expect(await screen.findByRole("heading", { name: "Controller view unavailable" })).toBeInTheDocument();
    expect(screen.getByText("No controller state was changed.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /try again/i }));
    await waitFor(() => expect(screen.getByRole("heading", { name: "Agent graph" })).toBeInTheDocument());
    expect(loader).toHaveBeenCalledTimes(2);
  });

  it("retries a transient managed lifecycle start failure", async () => {
    const user = userEvent.setup();
    const starter = vi.fn().mockRejectedValueOnce(new Error("start failed")).mockResolvedValueOnce(undefined);
    const loader = vi.fn().mockResolvedValue(snapshotFixture());
    render(<App startLifecycle={starter} loadSnapshot={loader} />);

    expect(await screen.findByRole("heading", { name: "Controller view unavailable" })).toBeInTheDocument();
    expect(loader).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: /try again/i }));
    expect(await screen.findByRole("heading", { name: "Agent graph" })).toBeInTheDocument();
    expect(starter).toHaveBeenCalledTimes(2);
    expect(loader).toHaveBeenCalledOnce();
  });

  it("opens local graph settings without adding controller authority", async () => {
    const user = userEvent.setup();
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshotFixture()} loadIntegration={async () => integrationStatus()} />);
    await screen.findByRole("heading", { name: "Agent graph" });

    await user.click(screen.getByRole("button", { name: "Open settings" }));

    expect(screen.getByRole("dialog", { name: "Settings" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /GENERAL/i })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByText("ARMED + READY")).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "OpenCode offload" })).toBeChecked();
    expect(screen.getByRole("switch", { name: "Secure mode" })).toBeChecked();
    expect(screen.getByRole("switch", { name: "Secure mode" })).toBeDisabled();
    expect(screen.getByRole("switch", { name: "Bounded child agents" })).toBeDisabled();
    expect(screen.getByRole("switch", { name: "Direct file broker" })).toBeDisabled();
    expect(screen.getByRole("switch", { name: "Live change feed" })).toBeDisabled();
    expect(screen.getByRole("switch", { name: "Keep running in background" })).toBeDisabled();
    await user.click(screen.getByRole("tab", { name: /GUI/i }));
    expect(screen.getByRole("switch", { name: "Auto-rotate" })).toBeChecked();
    expect(screen.getByRole("switch", { name: "Dispatch routes" })).toBeChecked();
    expect(screen.getByRole("switch", { name: "Callback routes" })).toBeChecked();
    expect(screen.getByRole("switch", { name: "Depth field" })).toBeChecked();
    expect(screen.getByRole("switch", { name: "Node halos" })).toBeChecked();
    expect(screen.getByRole("switch", { name: "Distance fog" })).toBeChecked();
    expect(screen.getByRole("switch", { name: "Screen-facing labels" })).toBeChecked();
    expect(screen.queryByLabelText("Objective")).not.toBeInTheDocument();
  });

  it("persists visual preferences across app renders", async () => {
    const user = userEvent.setup();
    const first = render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshotFixture()} />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(screen.getByRole("button", { name: "Open settings" }));
    await user.click(screen.getByRole("tab", { name: /GUI/i }));
    await user.click(screen.getByRole("switch", { name: "Depth field" }));
    expect(screen.getByRole("switch", { name: "Depth field" })).not.toBeChecked();
    first.unmount();

    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshotFixture()} />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(screen.getByRole("button", { name: "Open settings" }));
    await user.click(screen.getByRole("tab", { name: /GUI/i }));
    expect(screen.getByRole("switch", { name: "Depth field" })).not.toBeChecked();
  });

  it("restores defaults and closes settings with Escape", async () => {
    const user = userEvent.setup();
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshotFixture()} />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(screen.getByRole("button", { name: "Open settings" }));
    await user.click(screen.getByRole("tab", { name: /GUI/i }));
    await user.click(screen.getByRole("switch", { name: "Node halos" }));
    await user.click(screen.getByRole("button", { name: "RESTORE GUI DEFAULTS" }));
    expect(screen.getByRole("switch", { name: "Node halos" })).toBeChecked();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Settings" })).not.toBeInTheDocument();
  });

  it("changes the real integration target once without polling", async () => {
    const user = userEvent.setup();
    const loadIntegration = vi.fn().mockResolvedValue(integrationStatus());
    const changeIntegration = vi.fn().mockResolvedValue(integrationStatus(false));
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshotFixture()} loadIntegration={loadIntegration} changeIntegration={changeIntegration} />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(screen.getByRole("button", { name: "Open settings" }));
    const toggle = await screen.findByRole("switch", { name: "OpenCode offload" });
    await user.click(toggle);
    expect(changeIntegration).not.toHaveBeenCalled();
    expect(screen.getByRole("alertdialog", { name: "Disarm OpenCode offload?" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "CONFIRM DISARM" }));

    await waitFor(() => expect(changeIntegration).toHaveBeenCalledWith(false));
    expect(await screen.findByText("DISARMED")).toBeInTheDocument();
    expect(loadIntegration).toHaveBeenCalledOnce();
    expect(changeIntegration).toHaveBeenCalledOnce();
  });

  it("confirms one supported LLM model and effort pair without auto-applying", async () => {
    const user = userEvent.setup();
    const loadLlmBehaviour = vi.fn().mockResolvedValue(llmStatus());
    const changeLlmBehaviour = vi.fn().mockResolvedValue(llmStatus("provider/model-b", "medium"));
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshotFixture()} loadLlmBehaviour={loadLlmBehaviour} changeLlmBehaviour={changeLlmBehaviour} />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(screen.getByRole("button", { name: "Open settings" }));
    await user.click(screen.getByRole("tab", { name: /LLM BEHAVIOUR/i }));

    expect(await screen.findByText("MODEL CONTROL READY")).toBeInTheDocument();
    expect(screen.getByText(/Applies to newly dispatched root tasks/)).toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "Model" }), "provider/model-b");
    expect(screen.getByRole("combobox", { name: "Reasoning effort" })).toHaveValue("medium");
    await user.click(screen.getByRole("button", { name: "REVIEW & APPLY" }));
    expect(changeLlmBehaviour).not.toHaveBeenCalled();
    expect(screen.getByRole("alertdialog", { name: "Apply LLM behaviour?" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "CONFIRM APPLY" }));

    await waitFor(() => expect(changeLlmBehaviour).toHaveBeenCalledWith("provider/model-b", "medium"));
    expect(changeLlmBehaviour).toHaveBeenCalledOnce();
    expect(loadLlmBehaviour).toHaveBeenCalledOnce();
  });

  it("does not claim secure state when integration status is unknown", async () => {
    const user = userEvent.setup();
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshotFixture()} loadIntegration={async () => { throw new Error("unavailable"); }} />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(screen.getByRole("button", { name: "Open settings" }));

    expect(await screen.findByText("STATE UNKNOWN")).toBeInTheDocument();
    expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "OpenCode offload" })).toBeDisabled();
  });

  it("updates the graph immediately when the durable event sequence advances", async () => {
    const initial = snapshotFixture();
    initial.snapshot_version.event_sequence = 27;
    initial.worker_graph.workers = initial.worker_graph.workers.map((worker) => ({
      ...worker,
      slot_state: "clear",
      work_id: null,
      agent_lifecycle: null,
      assignment_id: null,
      transport: { ...worker.transport, id: null, state: "idle" },
    }));
    const changed = structuredClone(initial);
    changed.snapshot_version.event_sequence = 28;
    changed.worker_graph.workers[0] = {
      ...changed.worker_graph.workers[0],
      slot_state: "assigned",
      work_id: "spark-settings-pass",
      agent_lifecycle: "persistent",
      assignment_id: "assignment-live",
      transport: { ...changed.worker_graph.workers[0].transport, id: "transport-live", state: "reserved" },
    };
    let release: ((snapshot: typeof changed) => void) | undefined;
    const firstChange = new Promise<typeof changed>((resolve) => { release = resolve; });
    const never = new Promise<typeof changed>(() => {});
    const watcher = vi.fn()
      .mockImplementationOnce(() => firstChange)
      .mockImplementationOnce(() => never);

    render(<App startLifecycle={async () => {}} loadSnapshot={async () => initial} watchSnapshot={watcher} />);
    await screen.findByRole("heading", { name: "Agent graph" });
    expect(watcher).toHaveBeenCalledWith(27);

    release?.(changed);

    expect(await screen.findByRole("button", { name: /PERSISTENT · spark-settings-pass/i })).toBeInTheDocument();
    await waitFor(() => expect(watcher).toHaveBeenCalledWith(28));
    expect(watcher).toHaveBeenCalledTimes(2);
  });

  it("keeps the last trusted graph visible if the live feed disconnects", async () => {
    const snapshot = snapshotFixture();
    const watcher = vi.fn().mockRejectedValue(new Error("disconnected"));
    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshot} watchSnapshot={watcher} />);

    expect(await screen.findByRole("heading", { name: "Agent graph" })).toBeInTheDocument();
    expect(await screen.findByText("Live updates paused. The last validated snapshot remains visible.")).toBeInTheDocument();
    expect(screen.getByLabelText(/Interactive 3D Fugue agent graph/i)).toBeInTheDocument();
    expect(watcher).toHaveBeenCalledOnce();
  });

  it("silently follows validated Fugue events for the selected transcript", async () => {
    const user = userEvent.setup();
    const initial = snapshotFixture();
    initial.snapshot_version.event_sequence = 27;
    const changed = structuredClone(initial);
    changed.snapshot_version.event_sequence = 28;
    const baseBundle = {
      thread_id: "session-tensorhost-1",
      slot_id: "tensorhost-1",
      work_id: "work-42",
      generation: 1,
      fetched_at: "2026-09-06T11:00:00Z",
      expires_at: "2026-09-06T11:05:00Z",
      redacted: [],
    };
    const loadTranscript = vi.fn()
      .mockResolvedValueOnce({ ...baseBundle, turns: [{ seq: 0, role: "agent", kind: "text", preview: "first message", state: "committed" }] })
      .mockResolvedValueOnce({ ...baseBundle, turns: [{ seq: 0, role: "agent", kind: "text", preview: "first message", state: "committed" }, { seq: 1, role: "agent", kind: "text", preview: "new message", state: "committed" }] });
    let release: ((snapshot: typeof changed) => void) | undefined;
    const firstChange = new Promise<typeof changed>((resolve) => { release = resolve; });
    const never = new Promise<typeof changed>(() => {});
    const watcher = vi.fn().mockImplementationOnce(() => firstChange).mockImplementationOnce(() => never);

    render(<App startLifecycle={async () => {}} loadSnapshot={async () => initial} watchSnapshot={watcher} loadTranscript={loadTranscript} />);
    await screen.findByRole("heading", { name: "Agent graph" });
    await user.click(screen.getByRole("button", { name: /TENSORHOST-1 PERSISTENT/i }));
    expect(await screen.findByText("first message")).toBeInTheDocument();

    release?.(changed);

    expect(await screen.findByText("new message")).toBeInTheDocument();
    expect(loadTranscript).toHaveBeenCalledTimes(2);
  });

  it("labels a local Codex queue acknowledgement without claiming consumption", async () => {
    const snapshot = snapshotFixture();
    snapshot.recent_activity = {
      status: "available",
      window_events: 200,
      agents: [{ agent_id: "tensorhost-1", last_sequence: 27, last_occurred_at: "2026-09-06T18:30:00Z" }],
      items: [{ sequence: 27, event_type: "callback.delivered", origin: "tensorhost-1", destination: "source", occurred_at: "2026-09-06T18:30:00Z" }],
      content_included: false,
    };

    render(<App startLifecycle={async () => {}} loadSnapshot={async () => snapshot} />);

    expect(await screen.findByRole("log")).toHaveTextContent("callback queued to Codex");
    expect(screen.getByRole("log")).not.toHaveTextContent("callback delivered");
  });

  it("narrows agent recency by Fugue events or elapsed time", () => {
    const snapshot = snapshotFixture();
    snapshot.snapshot_version.event_sequence = 300;
    snapshot.recent_activity = {
      status: "available",
      window_events: 200,
      agents: [
        { agent_id: "control-1", last_sequence: 275, last_occurred_at: "2026-09-06T18:30:00Z" },
        { agent_id: "personal-1", last_sequence: 50, last_occurred_at: "2026-09-01T18:30:00Z" },
      ],
      items: [],
      content_included: false,
    };

    expect(activityAgentIsRecent(snapshot, "control-1", { ...DEFAULT_TOPOLOGY_SETTINGS, agentWindowEvents: 50 })).toBe(true);
    expect(activityAgentIsRecent(snapshot, "personal-1", { ...DEFAULT_TOPOLOGY_SETTINGS, agentWindowEvents: 50 })).toBe(false);
    expect(activityAgentIsRecent(snapshot, "control-1", { ...DEFAULT_TOPOLOGY_SETTINGS, agentWindowMode: "hours", agentWindowHours: 2 }, Date.parse("2026-09-06T19:00:00Z"))).toBe(true);
  });
});
