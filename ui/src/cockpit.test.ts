import { invoke } from "@tauri-apps/api/core";
import { fetchCockpitSnapshot, startFugueLifecycle, watchCockpitSnapshot } from "./cockpit";
import { snapshotFixture } from "./test/fixture";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

describe("cockpit command adapter", () => {
  it("invokes the single read-only snapshot command", async () => {
    vi.mocked(invoke).mockResolvedValue(snapshotFixture());
    await expect(fetchCockpitSnapshot()).resolves.toMatchObject({ projection_version: 1 });
    expect(invoke).toHaveBeenCalledOnce();
    expect(invoke).toHaveBeenCalledWith("cockpit_snapshot");
  });

  it("uses the fixed managed lifecycle command", async () => {
    vi.mocked(invoke).mockResolvedValue(undefined);
    await expect(startFugueLifecycle()).resolves.toBeUndefined();
    expect(invoke).toHaveBeenCalledWith("app_lifecycle_start");
  });

  it("waits from the exact last validated event sequence", async () => {
    const next = snapshotFixture();
    next.snapshot_version.event_sequence = 28;
    vi.mocked(invoke).mockResolvedValue(next);

    await expect(watchCockpitSnapshot(27)).resolves.toMatchObject({ projection_version: 1 });
    expect(invoke).toHaveBeenCalledWith("cockpit_watch", { afterEventSequence: 27 });
  });

  it("rejects a watch response that did not advance", async () => {
    const stale = snapshotFixture();
    stale.snapshot_version.event_sequence = 27;
    vi.mocked(invoke).mockResolvedValue(stale);

    await expect(watchCockpitSnapshot(27)).rejects.toThrow("stale_event_sequence");
  });
});
