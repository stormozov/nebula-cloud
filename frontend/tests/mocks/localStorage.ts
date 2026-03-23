import { vi } from "vitest";

/**
 * A single localStorage mock for all tests
 */
export const localStorageMock = (() => {
  let store: Record<string, string> = {};

  const mock = {
    getItem: vi.fn((key: string): string | null => {
      return store[key] ?? null;
    }),

    setItem: vi.fn((key: string, value: string): void => {
      store[key] = value;
    }),

    removeItem: vi.fn((key: string): void => {
      delete store[key];
    }),

    clear: vi.fn((): void => {
      store = {};
    }),

    get length(): number {
      return Object.keys(store).length;
    },

    key: vi.fn((index: number): string | null => {
      return Object.keys(store)[index] ?? null;
    }),

    _store: store,
  };

  return mock;
})();

/**
 * Helper: set auth tokens in localStorage
 */
export const setAuthTokens = (
  accessToken: string,
  refreshToken?: string,
): void => {
  const tokenData = JSON.stringify({
    accessToken: JSON.stringify(accessToken),
    ...(refreshToken && { refreshToken: JSON.stringify(refreshToken) }),
  });
  localStorageMock.setItem("persist:auth", tokenData);
};

/**
 * Helper: clear auth tokens from localStorage
 */
export const clearAuthTokens = (): void => {
  localStorageMock.removeItem("persist:auth");
};

/**
 * Helper: set invalid auth token in localStorage
 */
export const setInvalidAuthToken = (): void => {
  localStorageMock.setItem("persist:auth", "invalid-json");
};

/**
 * Helper: completely clear localStorage
 */
export const resetLocalStorage = (): void => {
  localStorageMock.clear();
};

/**
 * Helper: initialize localStorage mock
 */
export const initLocalStorageMock = (): void => {
  Object.defineProperty(window, "localStorage", {
    value: localStorageMock,
    writable: true,
    configurable: true,
  });
};
