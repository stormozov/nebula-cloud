import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useBadgeCopy } from "../lib/useBadgeCopy";
import { useViewportBoundary } from "../lib/useViewportBoundary";
import * as utils from "../lib/utils";
import { Badge } from "./Badge";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("../lib/useBadgeCopy");
vi.mock("../lib/useViewportBoundary");
vi.mock("../lib/utils", () => ({
  shouldHideBadge: vi.fn(),
  formatDisplayContent: vi.fn(),
}));

vi.mock("../../Icon", () => ({
  Icon: ({ name, className }: { name: string; className?: string }) => (
    <span data-testid="icon" className={className} data-icon-name={name} />
  ),
}));

// =============================================================================
// TESTS
// =============================================================================

describe("Badge", () => {
  let mockUseBadgeCopy: ReturnType<typeof vi.fn>;
  let mockUseViewportBoundary: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();

    mockUseBadgeCopy = useBadgeCopy as unknown as ReturnType<typeof vi.fn>;
    mockUseBadgeCopy.mockReturnValue({
      handleKeyDown: vi.fn(),
      combinedClickHandler: vi.fn(),
      handleCopy: vi.fn(),
    });

    mockUseViewportBoundary = useViewportBoundary as unknown as ReturnType<
      typeof vi.fn
    >;
    mockUseViewportBoundary.mockReturnValue({
      transform: "",
      isPositionReady: true,
    });

    (
      utils.shouldHideBadge as unknown as ReturnType<typeof vi.fn>
    ).mockReturnValue(false);
    (
      utils.formatDisplayContent as unknown as ReturnType<typeof vi.fn>
    ).mockImplementation((children) => children ?? null);
  });

  describe("rendering & visibility", () => {
    it("should render badge when not hidden", () => {
      (
        utils.shouldHideBadge as unknown as ReturnType<typeof vi.fn>
      ).mockReturnValue(false);
      (
        utils.formatDisplayContent as unknown as ReturnType<typeof vi.fn>
      ).mockReturnValue(5);

      render(<Badge>5</Badge>);

      expect(screen.getByText("5")).toBeInTheDocument();
    });

    it("should return null when badge should be hidden", () => {
      (
        utils.shouldHideBadge as unknown as ReturnType<typeof vi.fn>
      ).mockReturnValue(true);

      const { container } = render(<Badge>0</Badge>);

      expect(container.firstChild).toBeNull();
    });
  });

  describe("dot mode", () => {
    it("should render dot badge when dot is true", () => {
      (
        utils.formatDisplayContent as unknown as ReturnType<typeof vi.fn>
      ).mockReturnValue(null);

      render(<Badge dot>5</Badge>);

      const badge = screen.getByRole("presentation");
      expect(badge.className).toMatch(/badge--dot/);
      expect(screen.queryByText("5")).not.toBeInTheDocument();
    });
  });

  describe("positioning", () => {
    it("should apply position class and transform style", () => {
      mockUseViewportBoundary.mockReturnValue({
        transform: "translate(10px, 20px)",
        isPositionReady: true,
      });

      render(<Badge position="top-right">5</Badge>);

      const badge = screen.getByText("5").parentElement as HTMLElement;
      expect(badge).toBeTruthy();
      expect(badge.className).toMatch(/badge--top-right/);
      expect(badge.className).toMatch(/badge--position-ready/);
      expect(badge.style.transform).toBe("translate(10px, 20px)");
    });

    it("should not apply transform style when position missing", () => {
      render(<Badge>5</Badge>);

      const badge = screen.getByText("5").parentElement as HTMLElement;
      expect(badge).toBeTruthy();
      expect(badge.style.transform).toBeFalsy();
    });
  });

  describe("copyable behavior", () => {
    it("should render as button when copyable and not positioned", () => {
      const mockOnClick = vi.fn();
      mockUseBadgeCopy.mockReturnValue({
        combinedClickHandler: mockOnClick,
        handleKeyDown: vi.fn(),
        handleCopy: vi.fn(),
      });

      render(<Badge copyable>5</Badge>);
      const button = screen.getByRole("button", { name: "5" });

      expect(button.tagName).toBe("BUTTON");
      expect(button.className).toMatch(/badge--copyable/);
    });

    it("should render span with button role when copyable and positioned", () => {
      mockUseBadgeCopy.mockReturnValue({
        combinedClickHandler: vi.fn(),
        handleKeyDown: vi.fn(),
        handleCopy: vi.fn(),
      });

      render(
        <Badge copyable position="top-right">
          5
        </Badge>,
      );
      const element = screen.getByRole("button");

      expect(element.tagName).toBe("SPAN");
      expect(element).toHaveAttribute("tabIndex", "0");
      expect(element.className).toMatch(/badge--copyable/);
    });

    it("should call combinedClickHandler when clicked", async () => {
      const user = userEvent.setup();
      const mockClickHandler = vi.fn();
      mockUseBadgeCopy.mockReturnValue({
        combinedClickHandler: mockClickHandler,
        handleKeyDown: vi.fn(),
        handleCopy: vi.fn(),
      });

      render(<Badge copyable>5</Badge>);
      await user.click(screen.getByRole("button"));

      expect(mockClickHandler).toHaveBeenCalledTimes(1);
    });

    it("should call handleKeyDown on key press", async () => {
      const user = userEvent.setup();
      const mockKeyDownHandler = vi.fn();
      mockUseBadgeCopy.mockReturnValue({
        combinedClickHandler: vi.fn(),
        handleKeyDown: mockKeyDownHandler,
        handleCopy: vi.fn(),
      });

      render(<Badge copyable>5</Badge>);
      await user.tab();
      await user.keyboard("{Enter}");

      expect(mockKeyDownHandler).toHaveBeenCalledTimes(1);
    });
  });

  describe("icon", () => {
    it("should render icon component when icon prop given", () => {
      render(<Badge icon="person">5</Badge>);

      const badge = screen.getByText("5").parentElement as HTMLElement;
      expect(badge).toBeTruthy();
      expect(badge.className).toMatch(/badge--with-icon/);

      const icon = screen.getByTestId("icon");
      expect(icon).toBeInTheDocument();
      expect(icon).toHaveAttribute("data-icon-name", "person");
    });
  });

  describe("variant styles", () => {
    it("should apply variant class based on prop", () => {
      render(<Badge variant="success">5</Badge>);

      const badge = screen.getByText("5").parentElement as HTMLElement;
      expect(badge).toBeTruthy();
      expect(badge.className).toMatch(/badge--success/);
    });
  });

  describe("superscript mode", () => {
    it("should apply superscript class when superscript true and not positioned", () => {
      render(<Badge superscript>5</Badge>);

      const badge = screen.getByText("5").parentElement as HTMLElement;
      expect(badge).toBeTruthy();
      expect(badge.className).toMatch(/badge--superscript/);
    });

    it("should not apply superscript class when positioned", () => {
      render(
        <Badge superscript position="bottom-left">
          5
        </Badge>,
      );

      const badge = screen.getByText("5").parentElement as HTMLElement;
      expect(badge).toBeTruthy();
      expect(badge.className).not.toMatch(/badge--superscript/);
    });
  });

  describe("maxCount formatting", () => {
    it("should display formatted content", () => {
      (
        utils.formatDisplayContent as unknown as ReturnType<typeof vi.fn>
      ).mockReturnValue("99+");

      render(<Badge maxCount={99}>100</Badge>);

      expect(screen.getByText("99+")).toBeInTheDocument();
    });
  });

  describe("accessibility", () => {
    it("should have role status for non-interactive badge", () => {
      render(<Badge>5</Badge>);

      expect(screen.getByRole("status")).toBeInTheDocument();
    });

    it("should have role presentation for dot badge", () => {
      render(<Badge dot />);

      expect(screen.getByRole("presentation")).toBeInTheDocument();
    });
  });

  describe("forwarded ref", () => {
    it("should forward ref to the root element", () => {
      const ref = React.createRef<HTMLSpanElement>();

      render(<Badge ref={ref}>5</Badge>);

      expect(ref.current).toBe(screen.getByText("5").parentElement);
    });
  });

  describe("additional props", () => {
    it("should spread additional props to the badge element", () => {
      render(
        <Badge data-testid="test-badge" aria-label="notifications">
          5
        </Badge>,
      );

      const badge = screen.getByTestId("test-badge");
      expect(badge).toHaveAttribute("aria-label", "notifications");
    });
  });
});
