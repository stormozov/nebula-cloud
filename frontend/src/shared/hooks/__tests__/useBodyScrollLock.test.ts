/* eslint-disable @typescript-eslint/no-explicit-any */
/** biome-ignore-all lint/suspicious/noExplicitAny: <for tests> */

import { renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// =============================================================================
// HELPERS
// =============================================================================

const { getScrollbarWidthMock } = vi.hoisted(() => ({
  getScrollbarWidthMock: vi.fn(),
}));

vi.mock("../../utils", () => ({
  getScrollbarWidth: getScrollbarWidthMock,
}));

let useBodyScrollLock: typeof import("../useBodyScrollLock").useBodyScrollLock;

beforeEach(async () => {
  vi.resetModules();
  const mod = await import("../useBodyScrollLock");
  useBodyScrollLock = mod.useBodyScrollLock;
});

const setScrollHeight = (value: number) => {
  Object.defineProperty(document.documentElement, "scrollHeight", {
    value,
    configurable: true,
    writable: true,
  });
};

const setInnerHeight = (value: number) => {
  vi.stubGlobal("innerHeight", value);
};

const restoreScrollHeight = () => {
  delete (document.documentElement as any).scrollHeight;
};

const restoreInnerHeight = () => {
  vi.unstubAllGlobals();
};

const resetBodyStyles = () => {
  document.body.style.overflow = "";
  document.body.style.paddingRight = "";
};

beforeEach(() => {
  getScrollbarWidthMock.mockReset();
  getScrollbarWidthMock.mockReturnValue(0);
  resetBodyStyles();
});

afterEach(() => {
  restoreScrollHeight();
  restoreInnerHeight();
  vi.restoreAllMocks();
});

// =============================================================================
// TESTS
// =============================================================================

describe("useBodyScrollLock", () => {
  // when isLocked becomes true
  describe("when isLocked becomes true", () => {
    it("should set body overflow to hidden when first lock is added", () => {
      setScrollHeight(500);
      setInnerHeight(800);

      renderHook(() => useBodyScrollLock(true));

      expect(document.body.style.overflow).toBe("hidden");
      expect(document.body.style.paddingRight).toBe("");
    });

    it("should add paddingRight when page has scroll and scrollbar width > 0", () => {
      setScrollHeight(1200);
      setInnerHeight(800);
      getScrollbarWidthMock.mockReturnValue(15);

      renderHook(() => useBodyScrollLock(true));

      expect(document.body.style.overflow).toBe("hidden");
      expect(document.body.style.paddingRight).toBe("15px");
    });

    it("should not add paddingRight when scrollbar width is 0", () => {
      setScrollHeight(1200);
      setInnerHeight(800);
      getScrollbarWidthMock.mockReturnValue(0);

      renderHook(() => useBodyScrollLock(true));

      expect(document.body.style.overflow).toBe("hidden");
      expect(document.body.style.paddingRight).toBe("");
    });

    it("should not add paddingRight when page has no scroll", () => {
      setScrollHeight(500);
      setInnerHeight(800);
      getScrollbarWidthMock.mockReturnValue(15);

      renderHook(() => useBodyScrollLock(true));

      expect(document.body.style.overflow).toBe("hidden");
      expect(document.body.style.paddingRight).toBe("");
    });
  });

  // when isLocked becomes false
  describe("when isLocked becomes false", () => {
    it("should remove overflow hidden when lock is released", () => {
      setScrollHeight(500);
      setInnerHeight(800);

      const { rerender } = renderHook(
        ({ isLocked }) => useBodyScrollLock(isLocked),
        {
          initialProps: { isLocked: true },
        },
      );
      expect(document.body.style.overflow).toBe("hidden");

      rerender({ isLocked: false });

      expect(document.body.style.overflow).toBe("");
    });

    it("should remove paddingRight when lock released after it was added", () => {
      setScrollHeight(1200);
      setInnerHeight(800);
      getScrollbarWidthMock.mockReturnValue(15);

      const { rerender } = renderHook(
        ({ isLocked }) => useBodyScrollLock(isLocked),
        {
          initialProps: { isLocked: true },
        },
      );
      expect(document.body.style.paddingRight).toBe("15px");

      rerender({ isLocked: false });

      expect(document.body.style.paddingRight).toBe("");
    });

    it("should not remove paddingRight that was not added", () => {
      document.body.style.paddingRight = "20px";
      setScrollHeight(1200);
      setInnerHeight(800);
      getScrollbarWidthMock.mockReturnValue(0);

      const { rerender } = renderHook(
        ({ isLocked }) => useBodyScrollLock(isLocked),
        {
          initialProps: { isLocked: true },
        },
      );
      expect(document.body.style.overflow).toBe("hidden");
      expect(document.body.style.paddingRight).toBe("20px");

      rerender({ isLocked: false });

      expect(document.body.style.overflow).toBe("");
      expect(document.body.style.paddingRight).toBe("20px");
    });
  });

  // multiple concurrent locks
  describe("multiple concurrent locks", () => {
    it("should release lock only when all locks are released", () => {
      setScrollHeight(1200);
      setInnerHeight(800);
      getScrollbarWidthMock.mockReturnValue(15);

      const hook1 = renderHook(({ isLocked }) => useBodyScrollLock(isLocked), {
        initialProps: { isLocked: true },
      });
      const hook2 = renderHook(({ isLocked }) => useBodyScrollLock(isLocked), {
        initialProps: { isLocked: true },
      });

      hook1.rerender({ isLocked: false });
      hook2.rerender({ isLocked: false });

      expect(document.body.style.overflow).toBe("");
      expect(document.body.style.paddingRight).toBe("");
    });
  });

  // unmount behavior
  describe("unmount behavior", () => {
    it("should release lock on unmount when component was locked", () => {
      setScrollHeight(1200);
      setInnerHeight(800);
      getScrollbarWidthMock.mockReturnValue(15);

      const { unmount } = renderHook(() => useBodyScrollLock(true));
      expect(document.body.style.overflow).toBe("hidden");

      unmount();

      expect(document.body.style.overflow).toBe("");
      expect(document.body.style.paddingRight).toBe("");
    });

    it("should not affect other locks when a locked component unmounts", () => {
      setScrollHeight(1200);
      setInnerHeight(800);
      getScrollbarWidthMock.mockReturnValue(15);

      const { unmount: unmount1 } = renderHook(() => useBodyScrollLock(true));
      const hook2 = renderHook(({ isLocked }) => useBodyScrollLock(isLocked), {
        initialProps: { isLocked: true },
      });

      unmount1();

      expect(document.body.style.overflow).toBe("hidden");
      expect(document.body.style.paddingRight).toBe("15px");

      hook2.rerender({ isLocked: false });
      expect(document.body.style.overflow).toBe("");
    });
  });

  // dynamic isLocked changes
  describe("dynamic isLocked changes", () => {
    it("should apply lock when isLocked toggles from false to true", () => {
      setScrollHeight(500);
      setInnerHeight(800);

      const { rerender } = renderHook(
        ({ isLocked }) => useBodyScrollLock(isLocked),
        {
          initialProps: { isLocked: false },
        },
      );
      expect(document.body.style.overflow).toBe("");

      rerender({ isLocked: true });

      expect(document.body.style.overflow).toBe("hidden");
    });

    it("should release lock when toggling from true to false with no other locks", () => {
      setScrollHeight(500);
      setInnerHeight(800);

      const { rerender } = renderHook(
        ({ isLocked }) => useBodyScrollLock(isLocked),
        {
          initialProps: { isLocked: true },
        },
      );
      expect(document.body.style.overflow).toBe("hidden");

      rerender({ isLocked: false });

      expect(document.body.style.overflow).toBe("");
    });
  });
});
