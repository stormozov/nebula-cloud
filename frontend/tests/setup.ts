import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, vi } from "vitest";

import { initLocalStorageMock, resetLocalStorage } from "./mocks/localStorage";
import { server } from "./mocks/server";

initLocalStorageMock();

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  resetLocalStorage();
});

// Start MSW server
beforeAll(() => server.listen({ onUnhandledRequest: "warn" }));
afterAll(() => server.close());
afterEach(() => server.resetHandlers());

// Mock для redux-persist
vi.mock("redux-persist", async () => {
  const actual = await vi.importActual("redux-persist");
  return {
    ...(actual as object),
    persistStore: vi.fn((store) => ({
      ...store,
      _persist: { version: -1, rehydrated: true },
    })),
    persistReducer: vi.fn((_config, reducer) => reducer),
    FLUSH: "persist/FLUSH",
    REHYDRATE: "persist/REHYDRATE",
    PAUSE: "persist/PAUSE",
    PERSIST: "persist/PERSIST",
    PURGE: "persist/PURGE",
    REGISTER: "persist/REGISTER",
  };
});
