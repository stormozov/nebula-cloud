import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getScrollbarWidth } from "../getScrollbarWidth";

describe("getScrollbarWidth", () => {
  let mockDiv: {
    style: Record<string, string>;
    offsetWidth: number;
    clientWidth: number;
  };
  let appendMock: ReturnType<typeof vi.fn>;
  let removeChildMock: ReturnType<typeof vi.fn>;

  const createMockDiv = (offsetWidth = 120, clientWidth = 100) => ({
    style: {} as Record<string, string>,
    offsetWidth,
    clientWidth,
  });

  beforeEach(() => {
    vi.stubGlobal("window", {});

    appendMock = vi.fn();
    removeChildMock = vi.fn();
    const mockBody = {
      append: appendMock,
      removeChild: removeChildMock,
    };

    vi.spyOn(document, "createElement").mockImplementation((tag: string) => {
      if (tag === "div") {
        mockDiv = createMockDiv();
        return mockDiv as unknown as HTMLElement;
      }
      return {} as HTMLElement;
    });

    Object.defineProperty(document, "body", {
      value: mockBody,
      writable: true,
      configurable: true,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  // ---------------------------------------------------------------------------
  // Tests
  // ---------------------------------------------------------------------------

  describe("when in browser environment", () => {
    /**
     * @description Should calculate scrollbar width as offsetWidth minus clientWidth
     * @scenario Call getScrollbarWidth with default mock (offsetWidth 120, clientWidth 100)
     * @expected Returns 20
     */
    it("should return offsetWidth minus clientWidth when window is defined", () => {
      // Arrange
      // Act
      const width = getScrollbarWidth();

      // Assert
      expect(width).toBe(20);
    });

    /**
     * @description Should create a temporary div with scroll overflow and fixed dimensions
     * @scenario Call getScrollbarWidth and inspect the created element
     * @expected The div has overflow: scroll, width: 100px, height: 100px
     */
    it("should create a div with correct styles when measuring", () => {
      // Arrange
      // Act
      getScrollbarWidth();

      // Assert
      expect(document.createElement).toHaveBeenCalledWith("div");
      expect(mockDiv.style.overflow).toBe("scroll");
      expect(mockDiv.style.width).toBe("100px");
      expect(mockDiv.style.height).toBe("100px");
    });

    /**
     * @description Should append the div to body and remove it after measurement
     * @scenario Call getScrollbarWidth and check DOM manipulation
     * @expected Div is appended to body, then removed
     */
    it("should append and remove the div when called", () => {
      // Arrange
      // Act
      getScrollbarWidth();

      // Assert
      expect(appendMock).toHaveBeenCalledWith(mockDiv);
      expect(removeChildMock).toHaveBeenCalledWith(mockDiv);
    });

    /**
     * @description Should return 0 when scrollbar width is 0 (offsetWidth equals clientWidth)
     * @scenario Mock element with equal offsetWidth and clientWidth
     * @expected Returns 0
     */
    it("should return 0 when offsetWidth equals clientWidth", () => {
      // Arrange
      mockDiv = createMockDiv(100, 100);
      vi.mocked(document.createElement).mockReturnValue(
        mockDiv as unknown as HTMLElement,
      );

      // Act
      const width = getScrollbarWidth();

      // Assert
      expect(width).toBe(0);
    });
  });

  describe("when in server environment", () => {
    /**
     * @description Should return 0 without touching the DOM when window is undefined
     * @scenario Simulate SSR by setting window to undefined
     * @expected Returns 0, document.createElement is not called
     */
    it("should return 0 when window is undefined", () => {
      // Arrange
      vi.stubGlobal("window", undefined);

      // Act
      const width = getScrollbarWidth();

      // Assert
      expect(width).toBe(0);
      expect(document.createElement).not.toHaveBeenCalled();
    });
  });
});
