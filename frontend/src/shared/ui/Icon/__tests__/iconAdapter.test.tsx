import { render, screen } from "@testing-library/react";
import type { ComponentType, ReactElement, SVGProps } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createIconAdapter } from "../iconAdapter";
import type { ICustomIconProps } from "../types";

describe("createIconAdapter", () => {
  const MockRawIcon = vi.fn((props: SVGProps<SVGSVGElement>) => (
    <svg data-testid="mock-raw-icon" {...props}>
      <title>Accessible title</title>
      {props.children}
    </svg>
  )) as ComponentType<SVGProps<SVGSVGElement>>;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("when creating an icon adapter", () => {
    /**
     * @description Should return a React component that renders the RawIcon
     * @scenario Call createIconAdapter with a mock raw icon component
     * @expected Returned component renders the mock raw icon
     */
    it("should return a component that renders RawIcon", () => {
      // Arrange
      const AdaptedIcon = createIconAdapter(MockRawIcon);

      // Act
      render(<AdaptedIcon />);

      // Assert
      expect(screen.getByTestId("mock-raw-icon")).toBeInTheDocument();
    });

    /**
     * @description Should pass width and height props equal to size value
     * @scenario Render adapted icon with size="24px"
     * @expected RawIcon receives width="24px" and height="24px"
     */
    it("should pass width and height from size prop to RawIcon", () => {
      // Arrange
      const AdaptedIcon = createIconAdapter(MockRawIcon);
      const size = "24px";

      // Act
      render(<AdaptedIcon size={size} />);

      // Assert
      expect(vi.mocked(MockRawIcon).mock.calls[0][0]).toMatchObject({
        width: size,
        height: size,
      });
    });

    /**
     * @description Should use default size "1em" when size prop is not provided
     * @scenario Render adapted icon without size prop
     * @expected RawIcon receives width="1em" and height="1em"
     */
    it('should use default size "1em" when size is not provided', () => {
      // Arrange
      const AdaptedIcon = createIconAdapter(MockRawIcon);

      // Act
      render(<AdaptedIcon />);

      // Assert
      expect(vi.mocked(MockRawIcon).mock.calls[0][0]).toMatchObject({
        width: "1em",
        height: "1em",
      });
    });

    /**
     * @description Should pass fill prop equal to color value to RawIcon
     * @scenario Render adapted icon with color="red"
     * @expected RawIcon receives fill="red"
     */
    it("should pass fill from color prop to RawIcon", () => {
      // Arrange
      const AdaptedIcon = createIconAdapter(MockRawIcon);
      const color = "red";

      // Act
      render(<AdaptedIcon color={color} />);

      // Assert
      expect(vi.mocked(MockRawIcon).mock.calls[0][0]).toMatchObject({
        fill: color,
      });
    });

    /**
     * @description Should use default color "currentColor" when color prop is not provided
     * @scenario Render adapted icon without color prop
     * @expected RawIcon receives fill="currentColor"
     */
    it('should use default color "currentColor" when color is not provided', () => {
      // Arrange
      const AdaptedIcon = createIconAdapter(MockRawIcon);

      // Act
      render(<AdaptedIcon />);

      // Assert
      expect(vi.mocked(MockRawIcon).mock.calls[0][0]).toMatchObject({
        fill: "currentColor",
      });
    });

    /**
     * @description Should pass className prop to RawIcon
     * @scenario Render adapted icon with className="custom-icon"
     * @expected RawIcon receives className="custom-icon"
     */
    it("should pass className prop to RawIcon", () => {
      // Arrange
      const AdaptedIcon = createIconAdapter(MockRawIcon);
      const className = "custom-icon";

      // Act
      render(<AdaptedIcon className={className} />);

      // Assert
      expect(vi.mocked(MockRawIcon).mock.calls[0][0]).toMatchObject({
        className,
      });
    });

    /**
     * @description Should pass onClick prop to RawIcon
     * @scenario Render adapted icon with onClick handler
     * @expected RawIcon receives the same onClick function
     */
    it("should pass onClick prop to RawIcon", () => {
      // Arrange
      const AdaptedIcon = createIconAdapter(MockRawIcon);
      const onClick = vi.fn();

      // Act
      render(<AdaptedIcon onClick={onClick} />);

      // Assert
      expect(vi.mocked(MockRawIcon).mock.calls[0][0]).toMatchObject({
        onClick,
      });
    });

    /**
     * @description Should render <title> element inside SVG when title prop is provided
     * @scenario Render adapted icon with title="Accessible title"
     * @expected RawIcon receives children containing a <title> React element with correct text
     */
    it("should render title element inside RawIcon when title prop is provided", () => {
      // Arrange
      const AdaptedIcon = createIconAdapter(MockRawIcon);
      const titleText = "Accessible title";

      // Act
      render(<AdaptedIcon title={titleText} />);

      // Assert
      const children = vi.mocked(MockRawIcon).mock.calls[0][0].children as
        | ReactElement
        | undefined;

      expect(children).toBeDefined();
      expect(children?.type).toBe("title");
      const props = children?.props as { children?: string };
      expect(props?.children).toBe(titleText);
    });

    /**
     * @description Should not render <title> element when title prop is not provided
     * @scenario Render adapted icon without title prop
     * @expected RawIcon does not receive children (children is undefined)
     */
    it("should not render title element when title prop is omitted", () => {
      // Arrange
      const AdaptedIcon = createIconAdapter(MockRawIcon);

      // Act
      render(<AdaptedIcon />);

      // Assert
      expect(vi.mocked(MockRawIcon).mock.calls[0][0].children).toBeUndefined();
    });

    /**
     * @description Should handle numeric size by passing as number to RawIcon
     * @scenario Render adapted icon with size={32}
     * @expected RawIcon receives width={32} and height={32}
     */
    it("should pass numeric size as number to RawIcon", () => {
      // Arrange
      const AdaptedIcon = createIconAdapter(MockRawIcon);
      const size = 32;

      // Act
      render(<AdaptedIcon size={size} />);

      // Assert
      expect(vi.mocked(MockRawIcon).mock.calls[0][0]).toMatchObject({
        width: size,
        height: size,
      });
    });

    /**
     * @description Should combine all props correctly when multiple props are provided
     * @scenario Render adapted icon with size, color, className, onClick, and title
     * @expected RawIcon receives all props correctly
     */
    it("should pass all props together when multiple are provided", () => {
      // Arrange
      const AdaptedIcon = createIconAdapter(MockRawIcon);
      const props: ICustomIconProps = {
        size: "40px",
        color: "blue",
        className: "test-class",
        title: "Test Title",
        onClick: vi.fn(),
      };

      // Act
      render(<AdaptedIcon {...props} />);

      // Assert
      const calledProps = vi.mocked(MockRawIcon).mock.calls[0][0];
      expect(calledProps).toMatchObject({
        width: props.size,
        height: props.size,
        fill: props.color,
        className: props.className,
        onClick: props.onClick,
      });
      const children = calledProps.children as ReactElement | undefined;
      expect(children).toBeDefined();
      expect(children?.type).toBe("title");
      const titleProps = children?.props as { children?: string } | undefined;
      expect(titleProps?.children).toBe(props.title);
    });
  });
});
