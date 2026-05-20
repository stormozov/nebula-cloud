import { render, screen } from "@testing-library/react";
import type { Mock } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { FileSearchInput } from "@/features/file/file-search";
import { HelpKeyboardShortcutsButton } from "@/features/help";
import { useMediaQuery } from "@/shared/hooks";
import { ControlledInput, PageWrapper } from "@/shared/ui";
import { FileManagerHeader } from "../FileManagerHeader";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("@/features/file/file-search", () => ({
  FileSearchInput: vi.fn(() => <div data-testid="file-search-input" />),
}));

vi.mock("@/features/file/file-upload", () => ({
  FileUploadButton: vi.fn(({ children }) => (
    <div data-testid="file-upload-button">{children}</div>
  )),
}));

vi.mock("@/features/help", () => ({
  HelpKeyboardShortcutsButton: vi.fn(() => (
    <div data-testid="help-keyboard-shortcuts-button" />
  )),
}));

vi.mock("@/shared/ui", async () => {
  const actual = await vi.importActual("@/shared/ui");
  return {
    ...actual,
    BackButton: vi.fn(() => <div data-testid="back-button">Back</div>),
    Badge: vi.fn(({ children, copyable, variant, icon, superscript }) => (
      <div
        data-testid="badge"
        data-copyable={copyable}
        data-variant={variant}
        data-icon={icon}
        data-superscript={superscript}
      >
        {children}
      </div>
    )),
    ControlledInput: vi.fn(({ value, onChange, placeholder }) => (
      <input
        data-testid="controlled-input"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
    )),
    Heading: vi.fn(({ children, level, variant, align, noMargin }) => (
      <div
        data-testid="heading"
        data-level={level}
        data-variant={variant}
        data-align={align}
        data-no-margin={noMargin}
      >
        {children}
      </div>
    )),
    PageWrapper: vi.fn(
      ({ children, direction, align, justify, gap, fullWidth }) => (
        <div
          data-testid="page-wrapper"
          data-direction={direction}
          data-align={align}
          data-justify={justify}
          data-gap={gap}
          data-full-width={fullWidth}
        >
          {children}
        </div>
      ),
    ),
  };
});

vi.mock("@/shared/hooks", () => ({
  useMediaQuery: vi.fn(),
}));

// =============================================================================
// TESTS
// =============================================================================

describe("FileManagerHeader", () => {
  const mockOnSearchChange = vi.fn();
  const mockStorageWidget = <div data-testid="storage-widget">Storage</div>;

  beforeEach(() => {
    vi.clearAllMocks();
    (useMediaQuery as Mock).mockReturnValue(false);
  });

  describe("when isAdmin is false", () => {
    const defaultProps = {
      isAdmin: false,
      searchTerm: "",
      onSearchChange: mockOnSearchChange,
      storageWidget: mockStorageWidget,
    };

    describe("on desktop (isMobile600px = false)", () => {
      /**
       * @description Renders user mode header with desktop layout
       * @scenario isAdmin false, screen width > 600px (isMobile600px = false)
       * @expected No mobile search input, desktop FileSearchInput is visible, storageWidget is rendered
       */
      it("should render desktop header without mobile search input", () => {
        // Arrange
        (useMediaQuery as Mock).mockImplementation(({ query }) => {
          if (query === "(max-width: 600px)") return false;
          if (query === "(max-width: 440px)") return false;
          if (query === "(max-width: 375px)") return false;
          return false;
        });

        // Act
        render(<FileManagerHeader {...defaultProps} />);

        // Assert
        expect(screen.getByTestId("heading")).toHaveAttribute(
          "data-level",
          "2",
        );
        expect(screen.getByTestId("heading")).toHaveTextContent("Ваш диск");
        expect(screen.getByTestId("file-search-input")).toBeInTheDocument();
        expect(
          screen.getByTestId("help-keyboard-shortcuts-button"),
        ).toBeInTheDocument();
        expect(screen.getByTestId("file-upload-button")).toBeInTheDocument();
        expect(screen.getByTestId("storage-widget")).toBeInTheDocument();
        expect(
          screen.queryByTestId("controlled-input"),
        ).not.toBeInTheDocument();
      });

      /**
       * @description Passes searchTerm and onSearchChange to FileSearchInput props
       * @scenario isAdmin false, desktop layout, searchTerm provided
       * @expected FileSearchInput receives inputProps with value = searchTerm and onChange = onSearchChange
       */
      it("should pass searchTerm and onSearchChange to FileSearchInput", () => {
        // Arrange
        (useMediaQuery as Mock).mockReturnValue(false);
        const props = { ...defaultProps, searchTerm: "test search" };

        // Act
        render(<FileManagerHeader {...props} />);

        // Assert
        expect(FileSearchInput).toHaveBeenCalledTimes(1);
        const callArgs = (FileSearchInput as Mock).mock.calls[0][0];
        expect(callArgs.inputProps.value).toBe("test search");
        expect(callArgs.inputProps.onChange).toBe(mockOnSearchChange);
      });

      /**
       * @description FileUploadButton text is shown on desktop
       * @scenario isAdmin false, isMobile440px false
       * @expected FileUploadButton children = "Загрузить файл"
       */
      it("should show full text in FileUploadButton when not mobile 440px", () => {
        // Arrange
        (useMediaQuery as Mock).mockImplementation(({ query }) => {
          if (query === "(max-width: 440px)") return false;
          return false;
        });

        // Act
        render(<FileManagerHeader {...defaultProps} />);

        // Assert
        expect(screen.getByTestId("file-upload-button")).toHaveTextContent(
          "Загрузить файл",
        );
      });
    });

    describe("on mobile (isMobile600px = true)", () => {
      /**
       * @description Renders mobile search input (ControlledInput) when isMobile600px true
       * @scenario isAdmin false, screen width <= 600px
       * @expected ControlledInput is present, desktop FileSearchInput is not present
       */
      it("should render mobile search input instead of desktop FileSearchInput", () => {
        // Arrange
        (useMediaQuery as Mock).mockImplementation(({ query }) => {
          if (query === "(max-width: 600px)") return true;
          return false;
        });

        // Act
        render(<FileManagerHeader {...defaultProps} />);

        // Assert
        expect(screen.getByTestId("controlled-input")).toBeInTheDocument();
        expect(
          screen.queryByTestId("file-search-input"),
        ).not.toBeInTheDocument();
        expect(screen.getByTestId("storage-widget")).toBeInTheDocument();
      });

      /**
       * @description Passes searchTerm and onSearchChange to mobile ControlledInput
       * @scenario isAdmin false, isMobile600px true, searchTerm provided
       * @expected ControlledInput receives value = searchTerm, onChange = onSearchChange
       */
      it("should pass searchTerm and onSearchChange to mobile ControlledInput", () => {
        // Arrange
        (useMediaQuery as Mock).mockImplementation(
          ({ query }) => query === "(max-width: 600px)",
        );
        const props = { ...defaultProps, searchTerm: "mobile search" };

        // Act
        render(<FileManagerHeader {...props} />);

        // Assert
        expect(ControlledInput).toHaveBeenCalledTimes(1);
        const callArgs = (ControlledInput as unknown as Mock).mock.calls[0][0];
        expect(callArgs.value).toBe("mobile search");
        expect(callArgs.onChange).toBe(mockOnSearchChange);
      });
    });

    describe("when isMobile440px = true", () => {
      /**
       * @description Hides text inside FileUploadButton on small mobile
       * @scenario isAdmin false, isMobile440px true
       * @expected FileUploadButton children is empty string
       */
      it("should render empty string as FileUploadButton children", () => {
        // Arrange
        (useMediaQuery as Mock).mockImplementation(({ query }) => {
          if (query === "(max-width: 440px)") return true;
          return false;
        });

        // Act
        render(<FileManagerHeader {...defaultProps} />);

        // Assert
        expect(screen.getByTestId("file-upload-button")).toHaveTextContent("");
      });
    });
  });

  describe("when isAdmin is true", () => {
    const defaultProps = {
      isAdmin: true,
      userId: 12345,
      searchTerm: "",
      onSearchChange: mockOnSearchChange,
      storageWidget: mockStorageWidget,
    };

    describe("on desktop (isMobile600px = false)", () => {
      /**
       * @description Renders admin mode header with BackButton, user badge, and desktop search
       * @scenario isAdmin true, screen width > 600px
       * @expected BackButton is present, Heading contains Badge with userId, FileSearchInput has buttonProps with children "Поиск"
       */
      it("should render admin header with back button and user badge", () => {
        // Arrange
        (useMediaQuery as Mock).mockImplementation(({ query }) => {
          if (query === "(max-width: 600px)") return false;
          if (query === "(max-width: 375px)") return false;
          return false;
        });

        // Act
        render(<FileManagerHeader {...defaultProps} />);

        // Assert
        expect(screen.getByTestId("back-button")).toBeInTheDocument();
        expect(screen.getByTestId("heading")).toHaveTextContent(
          "Файлы пользователя",
        );
        const badge = screen.getByTestId("badge");
        expect(badge).toHaveTextContent("12345");
        expect(badge).toHaveAttribute("data-copyable", "true");
        expect(FileSearchInput).toHaveBeenCalledTimes(1);
        const callArgs = (FileSearchInput as Mock).mock.calls[0][0];
        expect(callArgs.buttonProps.children).toBe("Поиск");
        expect(screen.getByTestId("storage-widget")).toBeInTheDocument();
      });

      /**
       * @description Passes correct size props to buttons on desktop
       * @scenario isAdmin true, isMobile600px false
       * @expected FileSearchInput buttonProps.size = "small", HelpKeyboardShortcutsButton buttonProps.size = "small"
       */
      it('should pass size="small" to buttons when not mobile', () => {
        // Arrange
        (useMediaQuery as Mock).mockReturnValue(false);

        // Act
        render(<FileManagerHeader {...defaultProps} />);

        // Assert
        const fileSearchCall = (FileSearchInput as Mock).mock.calls[0][0];
        expect(fileSearchCall.buttonProps.size).toBe("small");

        const helpButtonCall = (HelpKeyboardShortcutsButton as Mock).mock
          .calls[0][0];
        expect(helpButtonCall.buttonProps.size).toBe("small");
      });
    });

    describe("on mobile (isMobile600px = true)", () => {
      /**
       * @description Adjusts button sizes to medium on mobile
       * @scenario isAdmin true, screen width <= 600px
       * @expected FileSearchInput buttonProps.size = "medium", HelpKeyboardShortcutsButton buttonProps.size = "medium"
       */
      it('should pass size="medium" to buttons on mobile', () => {
        // Arrange
        (useMediaQuery as Mock).mockImplementation(({ query }) => {
          if (query === "(max-width: 600px)") return true;
          return false;
        });

        // Act
        render(<FileManagerHeader {...defaultProps} />);

        // Assert
        const fileSearchCall = (FileSearchInput as Mock).mock.calls[0][0];
        expect(fileSearchCall.buttonProps.size).toBe("medium");

        const helpButtonCall = (HelpKeyboardShortcutsButton as Mock).mock
          .calls[0][0];
        expect(helpButtonCall.buttonProps.size).toBe("medium");
      });

      /**
       * @description Renders PageWrapper with column direction when mobile
       * @scenario isAdmin true, isMobile600px true
       * @expected PageWrapper receives direction="column"
       */
      it("should set PageWrapper direction to column on mobile", () => {
        // Arrange
        (useMediaQuery as Mock).mockImplementation(({ query }) => {
          if (query === "(max-width: 600px)") return true;
          return false;
        });

        // Act
        render(<FileManagerHeader {...defaultProps} />);

        // Assert
        const pageWrapperCalls = (PageWrapper as Mock).mock.calls;
        const topWrapperCall = pageWrapperCalls[0][0];
        expect(topWrapperCall.direction).toBe("column");
      });
    });

    describe("when isMobile375px = true", () => {
      /**
       * @description Wraps BackButton and Heading in column on very small screens
       * @scenario isAdmin true, isMobile375px true
       * @expected Inner PageWrapper has direction="column" and align="center"
       */
      it("should stack back button and heading vertically", () => {
        // Arrange
        (useMediaQuery as Mock).mockImplementation(({ query }) => {
          if (query === "(max-width: 375px)") return true;
          return false;
        });

        // Act
        render(<FileManagerHeader {...defaultProps} />);

        // Assert
        const pageWrapperCalls = (PageWrapper as Mock).mock.calls;
        const innerWrapperCall = pageWrapperCalls[1][0];
        expect(innerWrapperCall.direction).toBe("column");
        expect(innerWrapperCall.align).toBe("center");
      });
    });
  });

  describe("storageWidget prop", () => {
    /**
     * @description Renders storageWidget when provided in user mode
     * @scenario isAdmin false, storageWidget passed
     * @expected storageWidget is present in the DOM
     */
    it("should render storageWidget in user mode", () => {
      // Arrange
      (useMediaQuery as Mock).mockReturnValue(false);

      // Act
      render(
        <FileManagerHeader
          isAdmin={false}
          searchTerm=""
          onSearchChange={mockOnSearchChange}
          storageWidget={mockStorageWidget}
        />,
      );

      // Assert
      expect(screen.getByTestId("storage-widget")).toBeInTheDocument();
    });

    /**
     * @description Renders storageWidget when provided in admin mode
     * @scenario isAdmin true, storageWidget passed
     * @expected storageWidget is present in the DOM
     */
    it("should render storageWidget in admin mode", () => {
      // Arrange
      (useMediaQuery as Mock).mockReturnValue(false);

      // Act
      render(
        <FileManagerHeader
          isAdmin={true}
          userId={1}
          searchTerm=""
          onSearchChange={mockOnSearchChange}
          storageWidget={mockStorageWidget}
        />,
      );

      // Assert
      expect(screen.getByTestId("storage-widget")).toBeInTheDocument();
    });
  });
});
