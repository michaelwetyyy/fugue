import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  DEFAULT_TOPOLOGY_SETTINGS,
  loadTopologySettings,
  saveTopologySettings,
} from "./SettingsPage";

const STORAGE_KEY = "fugue.topology-settings.v1";
const originalStorage = Object.getOwnPropertyDescriptor(window, "localStorage");

describe("topology settings", () => {
  beforeAll(() => {
    const values = new Map<string, string>();
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: {
        clear: () => values.clear(),
        getItem: (key: string) => values.get(key) ?? null,
        removeItem: (key: string) => values.delete(key),
        setItem: (key: string, value: string) => values.set(key, value),
      },
    });
  });
  afterAll(() => {
    if (originalStorage) Object.defineProperty(window, "localStorage", originalStorage);
    else delete (window as unknown as { localStorage?: Storage }).localStorage;
  });
  beforeEach(() => window.localStorage.clear());

  it("migrates the exact legacy GUI preference shape without losing choices", () => {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({
      autoRotate: false,
      rotationSpeed: 1.1,
      showLabels: false,
      showDispatch: true,
      showCallbacks: false,
      showDepthField: true,
      showHalos: false,
      useFog: true,
    }));

    expect(loadTopologySettings()).toEqual({
      ...DEFAULT_TOPOLOGY_SETTINGS,
      autoRotate: false,
      rotationSpeed: 1.1,
      showLabels: false,
      showCallbacks: false,
      showHalos: false,
    });
  });

  it("round-trips the closed current shape and rejects values beyond authority", () => {
    const current = {
      ...DEFAULT_TOPOLOGY_SETTINGS,
      galaxyIdealDistance: 3.4,
      agentWindowMode: "hours" as const,
      agentWindowHours: 48,
    };
    saveTopologySettings(current);
    expect(loadTopologySettings()).toEqual(current);

    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({
      ...current,
      agentWindowEvents: 225,
    }));
    expect(loadTopologySettings()).toEqual(DEFAULT_TOPOLOGY_SETTINGS);
  });
});
