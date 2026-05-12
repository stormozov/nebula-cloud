import { describe, expect, it } from "vitest";
import {
  calculateViewportAdjustments,
  calculateVirtualCoordinates,
  getAdjustedAnchorPositionTransform,
  getBasePercentageOffsets,
} from "../getAdjustedAnchorPositionTransform";
import type { AnchorPosition } from "@/shared/types/common";

// Helpers to create fake DOMRect
const createFakeDOMRect = (
  x = 100,
  y = 200,
  width = 300,
  height = 150,
): DOMRect =>
  ({
    x,
    y,
    width,
    height,
    left: x,
    right: x + width,
    top: y,
    bottom: y + height,
    toJSON: () => ({}),
  }) as DOMRect;

// ---------------------------------------------------------------------------
// getBasePercentageOffsets
// ---------------------------------------------------------------------------
describe("getBasePercentageOffsets", () => {
  describe("when position starts with top", () => {
    /**
     * @description Should set baseYPercent to -50
     * @scenario Call with "top-left", "top-center", "top-right"
     * @expected baseYPercent is -50, baseXPercent depends on suffix
     */
    it("should set baseYPercent to -50 for top positions", () => {
      // Arrange
      // Act
      const result1 = getBasePercentageOffsets("top-left");
      const result2 = getBasePercentageOffsets("top-center");
      const result3 = getBasePercentageOffsets("top-right");

      // Assert
      expect(result1.baseYPercent).toBe(-50);
      expect(result2.baseYPercent).toBe(-50);
      expect(result3.baseYPercent).toBe(-50);
    });
  });

  describe("when position starts with bottom", () => {
    /**
     * @description Should set baseYPercent to 50
     * @scenario Call with "bottom-left", "bottom-center", "bottom-right"
     * @expected baseYPercent is 50
     */
    it("should set baseYPercent to 50 for bottom positions", () => {
      // Arrange
      // Act
      const result = getBasePercentageOffsets("bottom-right");

      // Assert
      expect(result.baseYPercent).toBe(50);
    });
  });

  describe('when position starts with other than top/bottom (e.g. only "left" or "center")', () => {
    // Assuming AnchorPosition type only allows valid combinations,
    // but if position could just be "left" or "center" without vertical prefix?
    // Likely type is "top-left" | "top-center" | "top-right" | "bottom-left" | "bottom-center" | "bottom-right".
    // But the function checks startsWith, so if only "left" is passed, baseYPercent stays 0.
    // We'll test a hypothetical invalid position to cover default path.
    // Since the type likely restricts, we'll cast to AnchorPosition.
    /**
     * @description Should keep baseYPercent as 0 when no top/bottom prefix
     * @scenario Call with "left" (if type allowed)
     * @expected baseYPercent is 0, baseXPercent -50
     */
    it("should default baseYPercent to 0 if position does not start with top or bottom", () => {
      // Arrange
      // Act
      const result = getBasePercentageOffsets("left" as AnchorPosition);

      // Assert
      expect(result.baseYPercent).toBe(0);
    });
  });

  describe("when position ends with left", () => {
    /**
     * @description Should set baseXPercent to -50
     * @scenario Call "top-left", "bottom-left"
     * @expected baseXPercent is -50
     */
    it("should set baseXPercent to -50 for left positions", () => {
      // Arrange
      // Act
      const result = getBasePercentageOffsets("top-left");

      // Assert
      expect(result.baseXPercent).toBe(-50);
    });
  });

  describe("when position ends with center", () => {
    /**
     * @description Should set baseXPercent to -50 (note: code uses -50 for center as well, probably centering logic)
     * @scenario Call "top-center", "bottom-center"
     * @expected baseXPercent is -50
     */
    it("should set baseXPercent to -50 for center positions (same as left)", () => {
      // Arrange
      // Act
      const result = getBasePercentageOffsets("top-center");

      // Assert
      expect(result.baseXPercent).toBe(-50);
    });
  });

  describe("when position ends with right", () => {
    /**
     * @description Should set baseXPercent to 50
     * @scenario Call "top-right", "bottom-right"
     * @expected baseXPercent is 50
     */
    it("should set baseXPercent to 50 for right positions", () => {
      // Arrange
      // Act
      const result = getBasePercentageOffsets("bottom-right");

      // Assert
      expect(result.baseXPercent).toBe(50);
    });
  });

  describe("when no horizontal suffix matched (should not happen with valid type)", () => {
    /**
     * @description Should keep baseXPercent 0 if no left/center/right suffix
     * @scenario Use "top" as invalid input
     * @expected baseXPercent = 0
     */
    it("should default baseXPercent to 0 for unknown suffix", () => {
      // Arrange
      // Act
      const result = getBasePercentageOffsets("top" as AnchorPosition);

      // Assert
      expect(result.baseXPercent).toBe(0);
    });
  });
});

// ---------------------------------------------------------------------------
// calculateVirtualCoordinates
// ---------------------------------------------------------------------------
describe("calculateVirtualCoordinates", () => {
  const rect = createFakeDOMRect(100, 200, 300, 150); // left:100, right:400, top:200, bottom:350

  /**
   * @description Should shift coordinates according to percentage offsets
   * @scenario baseXPercent = -50, baseYPercent = 50, rect as above
   * @expected shiftX = -150, shiftY = 75; left = -50, right = 250, top = 275, bottom = 425
   */
  it("should apply percentage shifts to rectangle edges", () => {
    // Arrange
    const baseXPercent = -50; // shiftX = 300 * -0.5 = -150
    const baseYPercent = 50; // shiftY = 150 * 0.5 = 75

    // Act
    const virtual = calculateVirtualCoordinates(
      rect,
      baseXPercent,
      baseYPercent,
    );

    // Assert
    expect(virtual.left).toBe(100 - 150); // -50
    expect(virtual.right).toBe(400 - 150); // 250
    expect(virtual.top).toBe(200 + 75); // 275
    expect(virtual.bottom).toBe(350 + 75); // 425
  });

  /**
   * @description Should handle zero percentage shifts
   * @scenario baseXPercent = 0, baseYPercent = 0
   * @expected No change to original rect coordinates
   */
  it("should not change coordinates when percentages are zero", () => {
    // Arrange
    const baseXPercent = 0;
    const baseYPercent = 0;

    // Act
    const virtual = calculateVirtualCoordinates(
      rect,
      baseXPercent,
      baseYPercent,
    );

    // Assert
    expect(virtual.left).toBe(rect.left);
    expect(virtual.right).toBe(rect.right);
    expect(virtual.top).toBe(rect.top);
    expect(virtual.bottom).toBe(rect.bottom);
  });

  /**
   * @description Should handle positive percentage shifts correctly
   * @scenario baseXPercent = 50, baseYPercent = -50
   * @expected shiftX = 150, shiftY = -75; left = 250, right = 550, top = 125, bottom = 275
   */
  it("should shift positively when percentages are positive", () => {
    // Arrange
    const baseXPercent = 50;
    const baseYPercent = -50;

    // Act
    const virtual = calculateVirtualCoordinates(
      rect,
      baseXPercent,
      baseYPercent,
    );

    // Assert
    expect(virtual.left).toBe(100 + 150);
    expect(virtual.right).toBe(400 + 150);
    expect(virtual.top).toBe(200 - 75);
    expect(virtual.bottom).toBe(350 - 75);
  });
});

// ---------------------------------------------------------------------------
// calculateViewportAdjustments
// ---------------------------------------------------------------------------
describe("calculateViewportAdjustments", () => {
  const viewportWidth = 800;
  const viewportHeight = 600;
  const padding = 10;

  /**
   * @description Should return zero adjustments when virtual element is fully inside viewport with padding
   * @scenario Virtual coordinates are within bounds
   * @expected adjustX = 0, adjustY = 0
   */
  it("should return zero adjustments when inside viewport", () => {
    // Arrange
    const virtual = { left: 50, right: 200, top: 50, bottom: 200 };

    // Act
    const adjustments = calculateViewportAdjustments(
      virtual,
      viewportWidth,
      viewportHeight,
      padding,
    );

    // Assert
    expect(adjustments.adjustX).toBe(0);
    expect(adjustments.adjustY).toBe(0);
  });

  /**
   * @description Should adjust X when virtual left is less than padding
   * @scenario virtual.left = 5, padding = 10
   * @expected adjustX = 5 (padding - left)
   */
  it("should adjust X when virtual left overflows left edge", () => {
    // Arrange
    const virtual = { left: 5, right: 300, top: 50, bottom: 200 };

    // Act
    const adjustments = calculateViewportAdjustments(
      virtual,
      viewportWidth,
      viewportHeight,
      padding,
    );

    // Assert
    expect(adjustments.adjustX).toBe(padding - virtual.left); // 5
    expect(adjustments.adjustY).toBe(0);
  });

  /**
   * @description Should adjust X when virtual right exceeds viewportWidth - padding
   * @scenario virtual.right = 795, viewportWidth=800, padding=10
   * @expected adjustX = (800 - 10) - 795 = -5
   */
  it("should adjust X when virtual right overflows right edge", () => {
    // Arrange
    const virtual = { left: 500, right: 795, top: 50, bottom: 200 };

    // Act
    const adjustments = calculateViewportAdjustments(
      virtual,
      viewportWidth,
      viewportHeight,
      padding,
    );

    // Assert
    expect(adjustments.adjustX).toBe(viewportWidth - padding - virtual.right); // -5
    expect(adjustments.adjustY).toBe(0);
  });

  /**
   * @description Should adjust Y when virtual top is less than padding
   * @scenario virtual.top = 3, padding = 10
   * @expected adjustY = 7
   */
  it("should adjust Y when virtual top overflows top edge", () => {
    // Arrange
    const virtual = { left: 50, right: 200, top: 3, bottom: 200 };

    // Act
    const adjustments = calculateViewportAdjustments(
      virtual,
      viewportWidth,
      viewportHeight,
      padding,
    );

    // Assert
    expect(adjustments.adjustY).toBe(padding - virtual.top); // 7
  });

  /**
   * @description Should adjust Y when virtual bottom exceeds viewportHeight - padding
   * @scenario virtual.bottom = 595, viewportHeight=600, padding=10
   * @expected adjustY = (600-10) - 595 = -5
   */
  it("should adjust Y when virtual bottom overflows bottom edge", () => {
    // Arrange
    const virtual = { left: 50, right: 200, top: 400, bottom: 595 };

    // Act
    const adjustments = calculateViewportAdjustments(
      virtual,
      viewportWidth,
      viewportHeight,
      padding,
    );

    // Assert
    expect(adjustments.adjustY).toBe(viewportHeight - padding - virtual.bottom); // -5
  });

  /**
   * @description Should not adjust if left equals padding exactly (within tolerance)
   * @scenario virtual.left = padding (10)
   * @expected adjustX = 0
   */
  it("should not adjust when virtual left equals padding", () => {
    // Arrange
    const virtual = { left: padding, right: 200, top: 50, bottom: 200 };

    // Act
    const adjustments = calculateViewportAdjustments(
      virtual,
      viewportWidth,
      viewportHeight,
      padding,
    );

    // Assert
    expect(adjustments.adjustX).toBe(0);
  });

  /**
   * @description Should not adjust when virtual right equals viewportWidth - padding
   * @scenario virtual.right = 790, viewportWidth=800, padding=10
   * @expected adjustX = 0
   */
  it("should not adjust when virtual right equals viewport minus padding", () => {
    // Arrange
    const virtual = {
      left: 590,
      right: viewportWidth - padding,
      top: 50,
      bottom: 200,
    };

    // Act
    const adjustments = calculateViewportAdjustments(
      virtual,
      viewportWidth,
      viewportHeight,
      padding,
    );

    // Assert
    expect(adjustments.adjustX).toBe(0);
  });

  /**
   * @description Should apply both X and Y adjustments simultaneously when both overflow
   * @scenario virtual.left = 0, virtual.top = 0, virtual.right = 900, virtual.bottom = 700
   * @expected adjustX = 10, adjustY = 10 (to bring to padding)
   */
  it("should adjust both X and Y when overflowing on both axes", () => {
    // Arrange
    const virtual = { left: 0, right: 900, top: 0, bottom: 700 };

    // Act
    const adjustments = calculateViewportAdjustments(
      virtual,
      viewportWidth,
      viewportHeight,
      padding,
    );

    // Assert
    expect(adjustments.adjustX).toBe(padding); // 10
    expect(adjustments.adjustY).toBe(padding); // 10
  });
});

// ---------------------------------------------------------------------------
// getAdjustedAnchorPositionTransform (integration)
// ---------------------------------------------------------------------------
describe("getAdjustedAnchorPositionTransform", () => {
  const defaultRect = createFakeDOMRect(200, 300, 400, 200); // left 200, right 600, top 300, bottom 500
  const viewportWidth = 1024;
  const viewportHeight = 768;
  const padding = 8;

  /**
   * @description Should return a correct transform string when element fits inside viewport without adjustments
   * @scenario position "top-left" with elementRect that doesn't cause overflow (left=300, top=300, width=200, height=100, viewport 1024x768, padding=8)
   * @expected transform like translate(calc(-50% + 0px), calc(-50% + 0px))
   */
  it("should return transform with zero adjustments when no viewport overflow", () => {
    // Arrange
    const rect = createFakeDOMRect(300, 300, 200, 100);
    const params = {
      position: "top-left" as const,
      elementRect: rect,
      viewportWidth: 1024,
      viewportHeight: 768,
      padding: 8,
    };

    // Act
    const transform = getAdjustedAnchorPositionTransform(params);

    // Assert
    // baseXPercent: -50, baseYPercent: -50
    // shiftX = 200 * (-0.5) = -100 => left=300-100=200 (>8), right=500-100=400 (<1016)
    // shiftY = 100 * (-0.5) = -50 => top=300-50=250 (>8), bottom=400-50=350 (<760)
    // => adjustX=0, adjustY=0
    expect(transform).toBe("translate(calc(-50% + 0px), calc(-50% + 0px))");
  });

  /**
   * @description Should return a transform with positive adjustX when left edge overflows
   * @scenario position "top-left" but elementRect left is near 0, causing virtual left < padding
   * @expected transform includes positive adjustX
   */
  it("should add positive adjustX when virtual left overflows padding", () => {
    // Arrange
    const rect = createFakeDOMRect(0, 300, 400, 200); // left = 0 -> virtual.left = 0 + (-50% of 400) = -200
    const params = {
      position: "top-left" as const,
      elementRect: rect,
      viewportWidth,
      viewportHeight,
      padding,
    };

    // Act
    const transform = getAdjustedAnchorPositionTransform(params);

    // Assert
    // baseXPercent = -50, baseYPercent = -50
    // virtual.left = 0 + (-200) = -200, padding=8 => adjustX = 8 - (-200) = 208
    // virtual.top = 300 + (-100) = 200, >8 => adjustY=0
    expect(transform).toBe("translate(calc(-50% + 208px), calc(-50% + 0px))");
  });

  /**
   * @description Should return a transform with negative adjustX when right edge overflows
   * @scenario position "top-right", elementRect right near viewport edge, virtual.right > viewportWidth - padding
   * @expected transform includes negative adjustX
   */
  it("should add negative adjustX when virtual right overflows right edge", () => {
    // Arrange
    const rect = createFakeDOMRect(900, 300, 400, 200); // left 900, right 1300 on viewport 1024
    const params = {
      position: "top-right" as const,
      elementRect: rect,
      viewportWidth,
      viewportHeight,
      padding,
    };

    // Act
    const transform = getAdjustedAnchorPositionTransform(params);

    // Assert
    // baseXPercent = 50, baseYPercent=-50
    // shiftX = 400*0.5 = 200, virtual.right = 1300 + 200 = 1500, viewportWidth-padding=1016 => adjustX = 1016-1500 = -484
    expect(transform).toBe("translate(calc(50% + -484px), calc(-50% + 0px))");
  });

  /**
   * @description Should include adjustY when bottom overflows
   * @scenario position "bottom-right", elementRect near bottom edge
   * @expected transform includes negative adjustY
   */
  it("should add negative adjustY when virtual bottom overflows bottom edge", () => {
    // Arrange
    const rect = createFakeDOMRect(200, 700, 300, 200); // bottom = 900, viewportHeight=768
    const params = {
      position: "bottom-right" as const,
      elementRect: rect,
      viewportWidth,
      viewportHeight,
      padding,
    };

    // Act
    const transform = getAdjustedAnchorPositionTransform(params);

    // Assert
    // baseYPercent=50 -> shiftY = 100, virtual.bottom = 900+100=1000, viewportHeight-padding=760 => adjustY = 760-1000 = -240
    // baseXPercent=50 -> shiftX=150, virtual.right = (200+300)+150=650, within viewport, adjustX=0
    expect(transform).toBe("translate(calc(50% + 0px), calc(50% + -240px))");
  });

  /**
   * @description Should use default padding of 4 when not provided
   * @scenario Omit padding parameter, virtual left overflows but less than 4
   * @expected Uses 4 as padding for adjustment calculation
   */
  it("should default padding to 4 if not specified", () => {
    // Arrange
    const rect = createFakeDOMRect(2, 300, 400, 200); // left=2 -> virtual.left = 2 + (-200) = -198, padding default 4 => adjustX = 4 - (-198)=202
    const params = {
      position: "top-left" as const,
      elementRect: rect,
      viewportWidth,
      viewportHeight,
    };

    // Act
    const transform = getAdjustedAnchorPositionTransform(params);

    // Assert
    expect(transform).toBe("translate(calc(-50% + 202px), calc(-50% + 0px))");
  });

  /**
   * @description Should handle "top-center" position (center horizontally, baseXPercent = -50)
   * @scenario position "top-center", large viewport, no adjustments needed
   * @expected transform with baseXPercent -50, baseYPercent -50, zero adjustments
   */
  it("should produce correct transform for top-center position", () => {
    // Arrange
    const params = {
      position: "top-center" as const,
      elementRect: defaultRect,
      viewportWidth,
      viewportHeight,
      padding,
    };

    // Act
    const transform = getAdjustedAnchorPositionTransform(params);

    // Assert
    // baseXPercent = -50 (center is same as left in code), baseYPercent = -50
    // virtual.left = 200 + (-200) = 0, which is < padding=8 => adjustX = 8
    // Actually default rect left=200, width=400 -> shiftX=-200 -> virtual.left=0, adjustX=8
    expect(transform).toBe("translate(calc(-50% + 8px), calc(-50% + 0px))");
  });
});
