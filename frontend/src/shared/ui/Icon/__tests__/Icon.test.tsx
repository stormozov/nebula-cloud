import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Icon, type IconName } from "../Icon";
import * as iconsRegistry from "../iconsRegistry";

// =============================================================================
// MOCKS
// =============================================================================

const { createMockIcon } = vi.hoisted(() => {
  const createMockIcon = (testId: string) =>
    vi.fn((props: React.SVGProps<SVGSVGElement>) => (
      <svg data-testid={testId} {...props} />
    ));
  return { createMockIcon };
});

vi.mock("react-icons/ai", () => ({
  AiOutlineClose: createMockIcon("mock-close"),
}));
vi.mock("react-icons/bi", () => ({
  BiSolidDashboard: createMockIcon("mock-dashboard"),
}));
vi.mock("react-icons/bs", () => ({
  BsFillLightbulbFill: createMockIcon("mock-lightbulb-on"),
  BsInfoSquareFill: createMockIcon("mock-info"),
  BsLightbulbOffFill: createMockIcon("mock-lightbulb-off"),
}));
vi.mock("react-icons/fa", () => ({
  FaEye: createMockIcon("mock-eye"),
  FaFolder: createMockIcon("mock-folder"),
  FaKeyboard: createMockIcon("mock-keyboard"),
  FaLock: createMockIcon("mock-lock"),
  FaSave: createMockIcon("mock-save"),
  FaUpload: createMockIcon("mock-upload"),
  FaUserPlus: createMockIcon("mock-user-plus"),
  FaUserTimes: createMockIcon("mock-user-times"),
}));
vi.mock("react-icons/fa6", () => ({
  FaCheck: createMockIcon("mock-check"),
  FaComment: createMockIcon("mock-comment"),
  FaCopy: createMockIcon("mock-copy"),
  FaDownload: createMockIcon("mock-download"),
  FaFileExport: createMockIcon("mock-export"),
  FaLinkSlash: createMockIcon("mock-link-slash"),
  FaPencil: createMockIcon("mock-pencil"),
  FaQuestion: createMockIcon("mock-question"),
  FaShareNodes: createMockIcon("mock-share"),
  FaTrashCan: createMockIcon("mock-trash"),
  FaUser: createMockIcon("mock-user"),
}));
vi.mock("react-icons/fi", () => ({
  FiMoreVertical: createMockIcon("mock-more"),
}));
vi.mock("react-icons/io", () => ({
  IoIosArrowBack: createMockIcon("mock-arrow-left"),
  IoIosArrowForward: createMockIcon("mock-arrow-right"),
  IoIosCloud: createMockIcon("mock-cloud"),
}));
vi.mock("react-icons/io5", () => ({
  IoMenu: createMockIcon("mock-menu"),
  IoMoon: createMockIcon("mock-moon"),
  IoReloadSharp: createMockIcon("mock-retry"),
  IoSearch: createMockIcon("mock-search"),
}));
vi.mock("react-icons/md", () => ({
  MdEdit: createMockIcon("mock-edit"),
  MdLogin: createMockIcon("mock-login"),
  MdLogout: createMockIcon("mock-logout"),
  MdOutlineDoNotDisturbAlt: createMockIcon("mock-do-not-disturb"),
  MdSunny: createMockIcon("mock-sun"),
}));
vi.mock("react-icons/pi", () => ({
  PiMonitorFill: createMockIcon("mock-monitor"),
  PiPasswordBold: createMockIcon("mock-password"),
  PiWarningDiamondFill: createMockIcon("mock-warning"),
}));
vi.mock("react-icons/ri", () => ({
  RiAdminFill: createMockIcon("mock-admin"),
}));
vi.mock("react-icons/tb", () => ({
  TbError404: createMockIcon("mock-not-found"),
}));

// Mock custom SVG assets (already adapted in registry)
vi.mock("@/assets/images/icons/CloudBadIcon.svg?react", () => ({
  default: createMockIcon("mock-cloud-bad"),
}));
vi.mock("@/assets/images/icons/CloudLoadingIcon.svg?react", () => ({
  default: createMockIcon("mock-cloud-loading"),
}));
vi.mock("@/assets/images/icons/CloudWarningIcon.svg?react", () => ({
  default: createMockIcon("mock-cloud-warning"),
}));

// =============================================================================
// TESTS
// =============================================================================

describe("Icon", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("when rendering with valid icon name", () => {
    /**
     * @description Should render the icon component corresponding to the provided name
     * @scenario Render Icon with name="edit"
     * @expected Icon component is in the document and receives correct props from the registry
     */
    it("should render icon component when valid name provided", () => {
      // Arrange
      const editIcon = iconsRegistry.ICONS.edit as ReturnType<typeof vi.fn>;

      // Act
      render(<Icon name="edit" />);

      // Assert
      expect(editIcon).toHaveBeenCalled();
    });

    /**
     * @description Should pass size, color, className, title, onClick to the underlying icon component
     * @scenario Render Icon with all custom props: size, color, className, title, onClick
     * @expected Underlying icon component receives those props
     */
    it("should forward all props (size, color, className, title, onClick) to the icon component", async () => {
      // Arrange
      const mockOnClick = vi.fn();
      const TestIcon = iconsRegistry.ICONS.edit as ReturnType<typeof vi.fn>;

      // Act
      render(
        <Icon
          name="edit"
          size={32}
          color="error"
          className="custom-icon"
          title="Edit document"
          onClick={mockOnClick}
        />,
      );

      // Assert
      expect(TestIcon).toHaveBeenCalledWith(
        expect.objectContaining({
          size: 32,
          color: "var(--color-error)",
          className: "custom-icon",
          title: "Edit document",
          onClick: mockOnClick,
        }),
        undefined, // React passes second argument (ref) which is undefined here
      );
    });
  });

  describe("when rendering with size prop", () => {
    /**
     * @description Should set size to "1em" when size="currentSize" is passed
     * @scenario Render Icon with size="currentSize"
     * @expected Underlying icon receives size="1em"
     */
    it('should convert "currentSize" to "1em"', () => {
      // Arrange
      const TestIcon = iconsRegistry.ICONS.edit as ReturnType<typeof vi.fn>;

      // Act
      render(<Icon name="edit" size="currentSize" />);

      // Assert
      expect(TestIcon).toHaveBeenCalledWith(
        expect.objectContaining({ size: "1em" }),
        undefined,
      );
    });

    /**
     * @description Should pass numeric size as is
     * @scenario Render Icon with size={24}
     * @expected Underlying icon receives size={24}
     */
    it("should pass numeric size directly", () => {
      // Arrange
      const TestIcon = iconsRegistry.ICONS.edit as ReturnType<typeof vi.fn>;

      // Act
      render(<Icon name="edit" size={24} />);

      // Assert
      expect(TestIcon).toHaveBeenCalledWith(
        expect.objectContaining({ size: 24 }),
        undefined,
      );
    });
  });

  describe("when rendering with color prop", () => {
    /**
     * @description Should map semantic color names to CSS variable values
     * @scenario Provide color="primary", "success", "warning", "error", "info"
     * @expected Underlying icon receives corresponding CSS variable value
     */
    it.each([
      ["primary", "var(--color-primary)"],
      ["success", "var(--color-success)"],
      ["warning", "var(--color-warning)"],
      ["error", "var(--color-error)"],
      ["info", "var(--color-info)"],
      ["text-primary", "var(--color-text-primary)"],
      ["text-secondary", "var(--color-text-secondary)"],
      ["text-tertiary", "var(--color-text-tertiary)"],
      ["text-inverse", "var(--color-text-inverse)"],
    ])('should map "%s" to "%s"', (color, expectedValue) => {
      // Arrange
      const TestIcon = iconsRegistry.ICONS.edit as ReturnType<typeof vi.fn>;

      // Act
      render(<Icon name="edit" color={color} />);

      // Assert
      expect(TestIcon).toHaveBeenCalledWith(
        expect.objectContaining({ color: expectedValue }),
        undefined,
      );
    });

    /**
     * @description Should pass custom color string directly when not a known semantic name
     * @scenario Provide color="#FF0000"
     * @expected Underlying icon receives color="#FF0000"
     */
    it("should pass custom color string as-is", () => {
      // Arrange
      const TestIcon = iconsRegistry.ICONS.edit as ReturnType<typeof vi.fn>;

      // Act
      render(<Icon name="edit" color="#FF0000" />);

      // Assert
      expect(TestIcon).toHaveBeenCalledWith(
        expect.objectContaining({ color: "#FF0000" }),
        undefined,
      );
    });

    /**
     * @description Should keep "currentColor" as "currentColor" without mapping
     * @scenario Provide color="currentColor"
     * @expected Underlying icon receives color="currentColor"
     */
    it('should keep "currentColor" as "currentColor"', () => {
      // Arrange
      const TestIcon = iconsRegistry.ICONS.edit as ReturnType<typeof vi.fn>;

      // Act
      render(<Icon name="edit" color="currentColor" />);

      // Assert
      expect(TestIcon).toHaveBeenCalledWith(
        expect.objectContaining({ color: "currentColor" }),
        undefined,
      );
    });
  });

  describe("when icon name does not exist", () => {
    /**
     * @description Should return null and render nothing when invalid icon name is provided
     * @scenario Render Icon with name="nonExistentIcon"
     * @expected Component renders null, no DOM elements appear
     */
    it("should return null and not render any icon", () => {
      // Arrange & Act
      const { container } = render(
        <Icon name={"nonExistentIcon" as IconName} />,
      );

      // Assert
      expect(container.firstChild).toBeNull();
    });
  });

  describe("when using adapted icons from registry", () => {
    /**
     * @description Should render adapted icons (cloudBad, cloudWarning, cloudLoading) without errors
     * @scenario Render Icon with name="cloudBad", "cloudWarning", "cloudLoading"
     * @expected Each renders a non-null SVG element (mock)
     */
    it.each([
      { name: "cloudBad", testId: "mock-cloud-bad" },
      { name: "cloudWarning", testId: "mock-cloud-warning" },
      { name: "cloudLoading", testId: "mock-cloud-loading" },
    ] as const)("should render $name adapted icon component", ({
      name,
      testId,
    }) => {
      // Arrange & Act
      render(<Icon name={name} />);

      // Assert
      expect(screen.getByTestId(testId)).toBeInTheDocument();
    });
  });

  describe("when onClick handler is attached", () => {
    /**
     * @description Should call onClick callback when the icon is clicked
     * @scenario Render Icon with onClick mock, simulate click
     * @expected Mock function is called once
     */
    it("should trigger onClick when icon is clicked", async () => {
      // Arrange
      const handleClick = vi.fn();
      const user = userEvent.setup();
      render(<Icon name="edit" onClick={handleClick} />);
      const svg = screen.getByTestId("mock-edit");

      // Act
      await user.click(svg);

      // Assert
      expect(handleClick).toHaveBeenCalledTimes(1);
    });
  });

  describe("when className is provided", () => {
    /**
     * @description Should pass className to the underlying icon component
     * @scenario Render Icon with className="my-custom-class"
     * @expected Underlying component receives className="my-custom-class"
     */
    it("should forward className to icon component", () => {
      // Arrange
      const TestIcon = iconsRegistry.ICONS.edit as ReturnType<typeof vi.fn>;

      // Act
      render(<Icon name="edit" className="my-custom-class" />);

      // Assert
      expect(TestIcon).toHaveBeenCalledWith(
        expect.objectContaining({ className: "my-custom-class" }),
        undefined,
      );
    });
  });
});
