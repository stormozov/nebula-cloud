import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CopyIcon } from "./CopyIcon";

vi.mock("../Icon", () => ({
  Icon: vi.fn(({ name, onClick, className, ...rest }) => (
    // biome-ignore lint/a11y/noStaticElementInteractions: <For testing purposes>
    // biome-ignore lint/a11y/useKeyWithClickEvents: <For testing purposes>
    <div
      data-testid="icon"
      data-name={name}
      onClick={onClick}
      className={className}
      {...rest}
    >
      {name}
    </div>
  )),
}));

describe("CopyIcon", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("when initially rendered", () => {
    /**
     * @description Should render copy icon when copied state is false
     * @scenario Render CopyIcon without any interaction
     * @expected Data attribute "data-name" equals "copy"
     */
    it("should render copy icon when copied is false", () => {
      // Arrange
      render(<CopyIcon />);

      // Act
      const icon = screen.getByTestId("icon");

      // Assert
      expect(icon).toHaveAttribute("data-name", "copy");
    });
  });

  describe("when user clicks the icon", () => {
    /**
     * @description Should change icon from copy to check after click
     * @scenario User clicks on the icon
     * @expected Data attribute "data-name" changes to "check"
     */
    it("should change icon to check when clicked", async () => {
      // Arrange
      render(<CopyIcon />);
      const icon = screen.getByTestId("icon");

      // Act
      await act(async () => {
        icon.click();
      });

      // Assert
      expect(icon).toHaveAttribute("data-name", "check");
    });

    /**
     * @description Should revert icon from check back to copy after 1000ms
     * @scenario User clicks icon, then waits 1 second
     * @expected Data attribute "data-name" reverts to "copy" after timeout
     */
    it("should revert to copy icon after 1 second", () => {
      // Arrange
      vi.useFakeTimers();
      render(<CopyIcon />);
      const icon = screen.getByTestId("icon");

      // Act
      act(() => {
        icon.click();
      });
      expect(icon).toHaveAttribute("data-name", "check");

      act(() => {
        vi.advanceTimersByTime(1000);
      });

      // Assert
      expect(icon).toHaveAttribute("data-name", "copy");
    });

    /**
     * @description Should handle rapid clicks without multiple timeouts
     * @scenario User clicks icon twice within less than 1 second
     * @expected Icon stays "check" and resets only once after the last click
     */
    it("should handle rapid clicks correctly", () => {
      // Arrange
      vi.useFakeTimers();
      render(<CopyIcon />);
      const icon = screen.getByTestId("icon");

      // Act
      act(() => {
        icon.click();
        icon.click();
      });
      expect(icon).toHaveAttribute("data-name", "check");

      act(() => {
        vi.advanceTimersByTime(1000);
      });

      // Assert
      expect(icon).toHaveAttribute("data-name", "copy");
    });
  });

  describe("when iconProps are provided", () => {
    /**
     * @description Should merge custom className with default "copy-icon"
     * @scenario Pass iconProps with className="custom"
     * @expected Icon element has both "copy-icon" and "custom" classes
     */
    it("should merge className from iconProps with default class", () => {
      // Arrange
      render(
        <CopyIcon iconProps={{ name: "copy", className: "custom-class" }} />,
      );
      const icon = screen.getByTestId("icon");

      // Assert
      expect(icon).toHaveClass("copy-icon");
      expect(icon).toHaveClass("custom-class");
    });
  });
});
