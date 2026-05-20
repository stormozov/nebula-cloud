import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getInitialMatches, useMediaQuery } from "../useMediaQuery";

// =============================================================================
// HELPERS
// =============================================================================

/**
 * Helper to create a mock MediaQueryList object.
 * @param matches - The initial matches value.
 * @returns Mock object with matches, addEventListener, removeEventListener.
 */
function createMockMediaQueryList(matches = false) {
  return {
    matches,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  };
}

// =============================================================================
// TESTS: useMediaQuery
// =============================================================================

describe("useMediaQuery", () => {
  let matchMediaMock: ReturnType<typeof vi.fn>;
  let originalWindow: typeof globalThis.window;

  beforeEach(() => {
    originalWindow = globalThis.window;
    matchMediaMock = vi.fn();
    vi.stubGlobal("window", {
      ...originalWindow,
      matchMedia: matchMediaMock,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.stubGlobal("window", originalWindow);
  });

  describe("when the hook mounts with a media query", () => {
    /**
     * @description Should return the initial matches value from matchMedia
     * @scenario window.matchMedia returns { matches: true } for the given query
     * @expected The hook returns true
     */
    it("should return initial matches value", () => {
      // Arrange
      const mockList = createMockMediaQueryList(true);
      matchMediaMock.mockReturnValue(mockList);

      // Act
      const { result } = renderHook(() =>
        useMediaQuery({ query: "(max-width: 768px)" }),
      );

      // Assert
      expect(result.current).toBe(true);
    });
  });

  describe("when the media query state changes", () => {
    /**
     * @description Should update matches when the change event fires
     * @scenario A listener is registered; change event is emitted with matches: false
     * @expected The hook returns the updated boolean (false)
     */
    it("should update matches on change event", () => {
      // Arrange
      const mockList = createMockMediaQueryList(true);
      matchMediaMock.mockReturnValue(mockList);
      const { result } = renderHook(() =>
        useMediaQuery({ query: "(max-width: 768px)" }),
      );

      // Capture the registered listener
      const [[eventType, listener]] = mockList.addEventListener.mock.calls;
      expect(eventType).toBe("change");

      // Act: simulate change event
      act(() => {
        listener({ matches: false } as MediaQueryListEvent);
      });

      // Assert
      expect(result.current).toBe(false);
    });
  });

  describe("on unmount", () => {
    /**
     * @description Should remove the change event listener when the hook unmounts
     * @scenario The hook is rendered and then unmounted
     * @expected removeEventListener is called with 'change' and the same handler
     */
    it("should remove event listener on unmount", () => {
      // Arrange
      const mockList = createMockMediaQueryList(false);
      matchMediaMock.mockReturnValue(mockList);
      const { unmount } = renderHook(() =>
        useMediaQuery({ query: "(min-width: 0)" }),
      );

      // Act
      unmount();

      // Assert
      expect(mockList.removeEventListener).toHaveBeenCalledWith(
        "change",
        expect.any(Function),
      );
      const [, addedListener] = mockList.addEventListener.mock.calls[0];
      expect(mockList.removeEventListener).toHaveBeenCalledWith(
        "change",
        addedListener,
      );
    });
  });

  describe("when the query prop changes", () => {
    /**
     * @description Should re-subscribe to the new media query and clean up the old one
     * @scenario Render with query A, then rerender with query B
     * @expected Old listener is removed, new listener is added with the new query
     */
    it("should remove old listener and add new one on query change", () => {
      // Arrange
      const mockListA = createMockMediaQueryList(false);
      const mockListB = createMockMediaQueryList(true);
      matchMediaMock.mockReturnValue(mockListA); // first render uses A for both init & effect

      const { rerender } = renderHook(({ query }) => useMediaQuery({ query }), {
        initialProps: { query: "(min-width: 400px)" },
      });

      const oldListener = mockListA.addEventListener.mock.calls[0][1];

      // Act: change the mock so subsequent call uses B
      matchMediaMock.mockReturnValue(mockListB);
      rerender({ query: "(max-width: 800px)" });

      // Assert
      expect(mockListA.removeEventListener).toHaveBeenCalledWith(
        "change",
        oldListener,
      );
      expect(mockListB.addEventListener).toHaveBeenCalledWith(
        "change",
        expect.any(Function),
      );
      expect(matchMediaMock).toHaveBeenCalledTimes(3); // init, effect on mount, effect on rerender
      expect(matchMediaMock).toHaveBeenNthCalledWith(1, "(min-width: 400px)");
      expect(matchMediaMock).toHaveBeenNthCalledWith(2, "(min-width: 400px)");
      expect(matchMediaMock).toHaveBeenNthCalledWith(3, "(max-width: 800px)");
    });

    /**
     * @description Should not re-subscribe if the query reference changes but value is the same
     * @scenario Rerender with the same query string
     * @expected No additional addEventListener/removeEventListener calls
     */
    it("should not re-subscribe when the same query string is passed", () => {
      // Arrange
      const mockList = createMockMediaQueryList(true);
      matchMediaMock.mockReturnValue(mockList);

      const { rerender } = renderHook(({ query }) => useMediaQuery({ query }), {
        initialProps: { query: "(color)" },
      });

      // Clear call history to isolate rerender action
      matchMediaMock.mockClear();
      mockList.addEventListener.mockClear();
      mockList.removeEventListener.mockClear();

      // Act
      rerender({ query: "(color)" });

      // Assert
      expect(matchMediaMock).not.toHaveBeenCalled();
      expect(mockList.addEventListener).not.toHaveBeenCalled();
      expect(mockList.removeEventListener).not.toHaveBeenCalled();
    });
  });
});

// =============================================================================
// TESTS: getInitialMatches
// =============================================================================

describe("getInitialMatches", () => {
  const originalWindow = globalThis.window;

  beforeEach(() => {
    vi.stubGlobal("window", originalWindow);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /**
   * @description Should return false when window is undefined (SSR)
   * @scenario Called with any query while window is undefined
   * @expected Returns false
   */
  it("should return false when window is undefined", () => {
    // Arrange
    vi.stubGlobal("window", undefined);

    // Act
    const result = getInitialMatches("(min-width: 500px)");

    // Assert
    expect(result).toBe(false);
  });

  /**
   * @description Should return matchMedia result when window exists
   * @scenario window.matchMedia returns { matches: true }
   * @expected Returns true
   */
  it("should return matchMedia matches when window is defined", () => {
    // Arrange
    const mockList = { matches: true } as MediaQueryList;
    const matchMediaSpy = vi.fn().mockReturnValue(mockList);
    vi.stubGlobal("window", { ...originalWindow, matchMedia: matchMediaSpy });

    // Act
    const result = getInitialMatches("(prefers-color-scheme: dark)");

    // Assert
    expect(result).toBe(true);
    expect(matchMediaSpy).toHaveBeenCalledWith("(prefers-color-scheme: dark)");
  });
});
