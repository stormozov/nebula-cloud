import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, vi } from "vitest";

import { server } from "./mocks/server";

// Cleanup после каждого теста
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  localStorage.clear();
});

// Запуск MSW сервера
beforeAll(() => server.listen({ onUnhandledRequest: "warn" }));
afterAll(() => server.close());
afterEach(() => server.resetHandlers());

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: vi.fn((key: string) => {
      return store[key] ?? null;
    }),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = value;
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key];
    }),
    clear: vi.fn(() => {
      store = {};
    }),
    get length() {
      return Object.keys(store).length;
    },
    key: vi.fn((index: number) => {
      return Object.keys(store)[index] ?? null;
    }),
  };
})();

Object.defineProperty(window, "localStorage", {
  value: localStorageMock,
  writable: true,
});

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
