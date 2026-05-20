import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { StatusBadge } from "./StatusBadge";

vi.mock("@/shared/ui/Icon", () => ({
  Icon: ({
    name,
    color,
    "aria-hidden": ariaHidden,
  }: {
    name: string;
    color: string;
    "aria-hidden"?: boolean;
  }) => (
    <span
      data-testid="mock-icon"
      data-name={name}
      data-color={color}
      aria-hidden={ariaHidden}
    >
      icon
    </span>
  ),
}));

describe("StatusBadge", () => {
  describe("when isActive is true", () => {
    /**
     * @description Renders active status with check icon and success color for success variant
     * @scenario Render StatusBadge with isActive=true and variant="success"
     * @expected Icon has name="check" and color="success"
     */
    it("should render check icon with success color for success variant", () => {
      // Arrange & Act
      render(<StatusBadge isActive={true} variant="success" />);

      // Assert
      const icon = screen.getByTestId("mock-icon");
      expect(icon).toHaveAttribute("data-name", "check");
      expect(icon).toHaveAttribute("data-color", "success");
    });

    /**
     * @description Renders active status with close icon and error color for error variant
     * @scenario Render StatusBadge with isActive=true and variant="error"
     * @expected Icon has name="close" and color="error"
     */
    it("should render close icon with error color for error variant", () => {
      // Arrange & Act
      render(<StatusBadge isActive={true} variant="error" />);

      // Assert
      const icon = screen.getByTestId("mock-icon");
      expect(icon).toHaveAttribute("data-name", "close");
      expect(icon).toHaveAttribute("data-color", "error");
    });

    /**
     * @description Displays default active text "Да" when activeText not provided
     * @scenario Render StatusBadge with isActive=true
     * @expected Screen contains text "Да"
     */
    it('should display default active text "Да" when activeText is not provided', () => {
      // Arrange & Act
      render(<StatusBadge isActive={true} />);

      // Assert
      expect(screen.getByText("Да")).toBeInTheDocument();
    });

    /**
     * @description Displays custom active text when activeText prop is provided
     * @scenario Render StatusBadge with isActive=true and activeText="Connected"
     * @expected Screen contains text "Connected"
     */
    it("should display custom active text when activeText is provided", () => {
      // Arrange & Act
      render(<StatusBadge isActive={true} activeText="Connected" />);

      // Assert
      expect(screen.getByText("Connected")).toBeInTheDocument();
    });
  });

  describe("when isActive is false", () => {
    /**
     * @description Renders inactive status with close icon and error color for success variant
     * @scenario Render StatusBadge with isActive=false and variant="success"
     * @expected Icon has name="close" and color="error"
     */
    it("should render close icon with error color for success variant", () => {
      // Arrange & Act
      render(<StatusBadge isActive={false} variant="success" />);

      // Assert
      const icon = screen.getByTestId("mock-icon");
      expect(icon).toHaveAttribute("data-name", "close");
      expect(icon).toHaveAttribute("data-color", "error");
    });

    /**
     * @description Renders inactive status with check icon and success color for error variant
     * @scenario Render StatusBadge with isActive=false and variant="error"
     * @expected Icon has name="check" and color="success"
     */
    it("should render check icon with success color for error variant", () => {
      // Arrange & Act
      render(<StatusBadge isActive={false} variant="error" />);

      // Assert
      const icon = screen.getByTestId("mock-icon");
      expect(icon).toHaveAttribute("data-name", "check");
      expect(icon).toHaveAttribute("data-color", "success");
    });

    /**
     * @description Displays default inactive text "Нет" when inactiveText not provided
     * @scenario Render StatusBadge with isActive=false
     * @expected Screen contains text "Нет"
     */
    it('should display default inactive text "Нет" when inactiveText is not provided', () => {
      // Arrange & Act
      render(<StatusBadge isActive={false} />);

      // Assert
      expect(screen.getByText("Нет")).toBeInTheDocument();
    });

    /**
     * @description Displays custom inactive text when inactiveText prop is provided
     * @scenario Render StatusBadge with isActive=false and inactiveText="Disconnected"
     * @expected Screen contains text "Disconnected"
     */
    it("should display custom inactive text when inactiveText is provided", () => {
      // Arrange & Act
      render(<StatusBadge isActive={false} inactiveText="Disconnected" />);

      // Assert
      expect(screen.getByText("Disconnected")).toBeInTheDocument();
    });
  });

  describe("when iconOnly is true", () => {
    /**
     * @description Renders only icon without any text when iconOnly is true
     * @scenario Render StatusBadge with isActive=true and iconOnly=true
     * @expected Icon is present, but no text element is rendered
     */
    it("should render only icon and no text", () => {
      // Arrange & Act
      render(<StatusBadge isActive={true} iconOnly={true} />);

      // Assert
      expect(screen.getByTestId("mock-icon")).toBeInTheDocument();
      expect(screen.queryByText("Да")).not.toBeInTheDocument();
    });

    /**
     * @description Does not render span with status text when iconOnly is true
     * @scenario Render StatusBadge with isActive=false, iconOnly=true, custom text
     * @expected Text content not present even if activeText/inactiveText provided
     */
    it("should not render text span even when text props are provided", () => {
      // Arrange & Act
      render(
        <StatusBadge isActive={false} iconOnly={true} inactiveText="Offline" />,
      );

      // Assert
      expect(screen.queryByText("Offline")).not.toBeInTheDocument();
    });
  });

  describe("accessibility", () => {
    /**
     * @description Has role="status" on root element for screen readers
     * @scenario Render StatusBadge
     * @expected Root div has role="status"
     */
    it('should have role="status" on the root element', () => {
      // Arrange & Act
      render(<StatusBadge isActive={true} />);

      // Assert
      const root = screen.getByRole("status");
      expect(root).toBeInTheDocument();
    });

    /**
     * @description Has aria-label equal to the displayed text
     * @scenario Render StatusBadge with isActive=true and activeText="Active"
     * @expected Root element has aria-label="Active"
     */
    it("should have aria-label equal to the displayed text", () => {
      // Arrange & Act
      render(<StatusBadge isActive={true} activeText="Active" />);

      // Assert
      const root = screen.getByRole("status");
      expect(root).toHaveAttribute("aria-label", "Active");
    });

    /**
     * @description Icon has aria-hidden="true" to be ignored by screen readers
     * @scenario Render StatusBadge
     * @expected Icon element has aria-hidden="true"
     */
    it('should have icon with aria-hidden="true"', () => {
      // Arrange & Act
      render(<StatusBadge isActive={true} />);

      // Assert
      const icon = screen.getByTestId("mock-icon");
      expect(icon).toHaveAttribute("aria-hidden", "true");
    });
  });

  describe("styling classes", () => {
    /**
     * @description Applies center-x class when centerX is true
     * @scenario Render StatusBadge with centerX={true}
     * @expected Root element has class "center-x"
     */
    it('should apply "center-x" class when centerX is true', () => {
      // Arrange & Act
      const { container } = render(
        <StatusBadge isActive={true} centerX={true} />,
      );

      // Assert
      const root = container.firstChild as HTMLElement;
      expect(root).toHaveClass("center-x");
    });

    /**
     * @description Applies "icon-only" class when iconOnly is true
     * @scenario Render StatusBadge with iconOnly={true}
     * @expected Root element has class "icon-only"
     */
    it('should apply "icon-only" class when iconOnly is true', () => {
      // Arrange & Act
      const { container } = render(
        <StatusBadge isActive={true} iconOnly={true} />,
      );

      // Assert
      const root = container.firstChild as HTMLElement;
      expect(root).toHaveClass("icon-only");
    });

    /**
     * @description Applies custom className to root element
     * @scenario Render StatusBadge with className="custom-class"
     * @expected Root element includes "custom-class"
     */
    it("should apply custom className to root element", () => {
      // Arrange & Act
      const { container } = render(
        <StatusBadge isActive={true} className="my-badge" />,
      );

      // Assert
      const root = container.firstChild as HTMLElement;
      expect(root).toHaveClass("my-badge");
    });

    /**
     * @description Applies variant-specific class "status-badge--success" or "status-badge--error"
     * @scenario Render with variant="success" then with variant="error"
     * @expected Correct class is present
     */
    it("should apply variant-specific class based on variant prop", () => {
      // Arrange & Act
      const { container: successContainer } = render(
        <StatusBadge isActive={true} variant="success" />,
      );
      const { container: errorContainer } = render(
        <StatusBadge isActive={true} variant="error" />,
      );

      // Assert
      const successRoot = successContainer.firstChild as HTMLElement;
      const errorRoot = errorContainer.firstChild as HTMLElement;
      expect(successRoot).toHaveClass("status-badge--success");
      expect(errorRoot).toHaveClass("status-badge--error");
    });
  });

  describe("text color styling", () => {
    /**
     * @description Text span has success color CSS variable when config color is "success"
     * @scenario Render StatusBadge with isActive=true, variant="success" so config.color = "success"
     * @expected Span inline style color equals "var(--color-success)"
     */
    it("should set text color to var(--color-success) when config color is success", () => {
      // Arrange & Act
      render(<StatusBadge isActive={true} variant="success" activeText="OK" />);

      // Assert
      const textSpan = screen.getByText("OK");
      expect(textSpan.style.color).toBe("var(--color-success)");
    });

    /**
     * @description Text span has error color CSS variable when config color is "error"
     * @scenario Render StatusBadge with isActive=true, variant="error" so config.color = "error"
     * @expected Span inline style color equals "var(--color-error)"
     */
    it("should set text color to var(--color-error) when config color is error", () => {
      // Arrange & Act
      render(
        <StatusBadge isActive={true} variant="error" activeText="Error" />,
      );

      // Assert
      const textSpan = screen.getByText("Error");
      expect(textSpan.style.color).toBe("var(--color-error)");
    });
  });
});
