import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { FileIcon } from "../FileIcon";
import type { FileType } from "../types";
import { FILE_TYPE_ICONS, getFileType } from "../utils";

// =============================================================================
// TEST HELPERS
// =============================================================================
/**
 * Helper: creates test cases for file type to icon rendering
 * Covers all file types without testing utility logic
 */
const createFileTypeTestCases = () => [
  { filename: "photo.jpg", expectedType: "image" as FileType },
  { filename: "movie.mp4", expectedType: "video" as FileType },
  { filename: "song.mp3", expectedType: "audio" as FileType },
  { filename: "report.pdf", expectedType: "document" as FileType },
  { filename: "archive.zip", expectedType: "archive" as FileType },
  { filename: "script.ts", expectedType: "code" as FileType },
  { filename: "unknown.exe", expectedType: "unknown" as FileType },
];

// =============================================================================
// TEST SUITE
// =============================================================================
describe("FileIcon", () => {
  beforeEach(() => {
    // No mocks needed - component uses pure utilities
  });

  // ---------------------------------------------------------------------------
  //  Rendering tests
  // ---------------------------------------------------------------------------
  /**
   * Tests for component rendering behavior
   */
  describe("rendering", () => {
    /**
     * @description Renders without crashing
     * @scenario FileIcon component mounts with required props
     * @expected Component renders successfully
     */
    it("should render without crashing", () => {
      expect(() => render(<FileIcon filename="test.txt" />)).not.toThrow();
    });

    /**
     * @description Renders icon for each file type
     * @scenario Different file extensions provided
     * @expected Correct icon component rendered based on file type
     */
    it.each(
      createFileTypeTestCases(),
    )("should render icon for $expectedType: '$filename'", ({
      filename,
      expectedType,
    }) => {
      const { container } = render(<FileIcon filename={filename} />);

      // Icon should be rendered (SVG element from react-icons)
      const iconElement = container.querySelector("svg");
      expect(iconElement).toBeDefined();

      // Should have file-type-specific class
      expect(container.firstChild).toHaveClass(`file-icon--${expectedType}`);
    });

    /**
     * @description Applies base CSS class
     * @scenario Component renders with default props
     * @expected Has "file-icon" base class
     */
    it("should have base CSS class", () => {
      const { container } = render(<FileIcon filename="test.txt" />);
      expect(container.firstChild).toHaveClass("file-icon");
    });

    /**
     * @description Renders aria-label for accessibility
     * @scenario Component renders with any filename
     * @expected aria-label attribute present with Russian label
     */
    it.each([
      { filename: "photo.jpg", expectedLabel: "Изображение" },
      { filename: "movie.mp4", expectedLabel: "Видео" },
      { filename: "song.mp3", expectedLabel: "Аудио" },
      { filename: "report.pdf", expectedLabel: "Документ" },
      { filename: "archive.zip", expectedLabel: "Архив" },
      { filename: "script.ts", expectedLabel: "Код" },
      { filename: "unknown.exe", expectedLabel: "Файл" },
    ])("should render aria-label for '$filename': '$expectedLabel'", ({
      filename,
      expectedLabel,
    }) => {
      const { container } = render(<FileIcon filename={filename} />);

      // SVG doesn't have role="img", use querySelector instead
      const iconElement = container.querySelector("svg");
      expect(iconElement).toHaveAttribute("aria-label", expectedLabel);
    });
  });

  // ---------------------------------------------------------------------------
  //  Props tests
  // ---------------------------------------------------------------------------
  /**
   * Tests for component props behavior
   */
  describe("props", () => {
    /**
     * @description Handles size prop
     * @scenario Custom size value provided
     * @expected Icon rendered with specified size
     */
    it.each([
      { size: 16 },
      { size: 24 },
      { size: 32 },
      { size: 48 },
    ])("should handle size prop: $size", ({ size }) => {
      const { container } = render(
        <FileIcon filename="test.txt" size={size} />,
      );
      const iconElement = container.querySelector("svg");
      expect(iconElement).toHaveAttribute("width", size.toString());
      expect(iconElement).toHaveAttribute("height", size.toString());
    });

    /**
     * @description Uses default size when not provided
     * @scenario size prop omitted
     * @expected Icon rendered with default size 24
     */
    it("should use default size 24", () => {
      const { container } = render(<FileIcon filename="test.txt" />);
      const iconElement = container.querySelector("svg");
      expect(iconElement).toHaveAttribute("width", "24");
      expect(iconElement).toHaveAttribute("height", "24");
    });

    /**
     * @description Handles custom className prop
     * @scenario Additional CSS classes provided
     * @expected Classes merged with base classes
     */
    it.each([
      { className: "custom-class" },
      { className: "class1 class2" },
      { className: "icon-large" },
    ])("should handle custom className: '$className'", ({ className }) => {
      const { container } = render(
        <FileIcon filename="test.txt" className={className} />,
      );
      expect(container.firstChild).toHaveClass(className);
      expect(container.firstChild).toHaveClass("file-icon");
    });

    /**
     * @description Handles empty className gracefully
     * @scenario className prop is empty string
     * @expected Component renders without errors
     */
    it("should handle empty className", () => {
      const { container } = render(
        <FileIcon filename="test.txt" className="" />,
      );
      expect(container.firstChild).toHaveClass("file-icon");
    });

    /**
     * @description Controls title attribute via showTooltip
     * @scenario showTooltip is true
     * @expected title element present with Russian label
     */
    it.each([
      { filename: "photo.jpg", expectedTitle: "Изображение" },
      { filename: "movie.mp4", expectedTitle: "Видео" },
      { filename: "script.ts", expectedTitle: "Код" },
    ])("should show tooltip for '$filename' when showTooltip=true", ({
      filename,
      expectedTitle,
    }) => {
      const { container } = render(
        <FileIcon filename={filename} showTooltip={true} />,
      );

      const iconElement = container.querySelector("svg");
      // React Icons renders <title> as child element, not attribute
      const titleElement = iconElement?.querySelector("title");
      expect(titleElement?.textContent).toBe(expectedTitle);
    });

    /**
     * @description Hides title when showTooltip is false
     * @scenario showTooltip is false or omitted
     * @expected title element not present
     */
    it("should not show title when showTooltip=false", () => {
      const { container } = render(
        <FileIcon filename="test.txt" showTooltip={false} />,
      );

      const iconElement = container.querySelector("svg");
      const titleElement = iconElement?.querySelector("title");
      expect(titleElement).toBeNull();
    });

    /**
     * @description Uses default showTooltip value
     * @scenario showTooltip prop omitted
     * @expected title element not present (default false)
     */
    it("should use default showTooltip value", () => {
      const { container } = render(<FileIcon filename="test.txt" />);

      const iconElement = container.querySelector("svg");
      const titleElement = iconElement?.querySelector("title");
      expect(titleElement).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  //  CSS class tests
  // ---------------------------------------------------------------------------
  /**
   * Tests for CSS class application
   */
  describe("CSS classes", () => {
    /**
     * @description Applies file-type-specific modifier class
     * @scenario Component renders with different file types
     * @expected Class "file-icon--{type}" applied
     */
    it.each(
      createFileTypeTestCases(),
    )("should apply modifier class for $expectedType: '$filename'", ({
      filename,
      expectedType,
    }) => {
      const { container } = render(<FileIcon filename={filename} />);
      expect(container.firstChild).toHaveClass(`file-icon--${expectedType}`);
    });

    /**
     * @description Combines all CSS classes correctly
     * @scenario Component renders with custom className and file type
     * @expected All classes present: base, modifier, custom
     */
    it("should combine all CSS classes", () => {
      const { container } = render(
        <FileIcon filename="photo.jpg" className="custom-class" />,
      );
      const element = container.firstChild;

      expect(element).toHaveClass("file-icon");
      expect(element).toHaveClass("file-icon--image");
      expect(element).toHaveClass("custom-class");
    });
  });

  // ---------------------------------------------------------------------------
  //  Integration tests
  // ---------------------------------------------------------------------------
  /**
   * Integration tests - component works with utilities
   */
  describe("integration", () => {
    /**
     * @description Complete rendering workflow
     * @scenario FileIcon renders with filename
     * @expected Utilities called, icon rendered with correct props
     */
    it("should complete full rendering workflow", () => {
      const filename = "presentation.pptx";
      const expectedType = getFileType(filename); // "document"

      const { container } = render(
        <FileIcon
          filename={filename}
          size={32}
          className="test-class"
          showTooltip={true}
        />,
      );

      const element = container.firstChild;
      const iconElement = container.querySelector("svg");

      // Verify classes
      expect(element).toHaveClass("file-icon");
      expect(element).toHaveClass(`file-icon--${expectedType}`);
      expect(element).toHaveClass("test-class");

      // Verify icon props
      expect(iconElement).toHaveAttribute("width", "32");
      expect(iconElement).toHaveAttribute("height", "32");
      expect(iconElement).toHaveAttribute("aria-label");

      // React Icons renders <title> as child element, not attribute
      const titleElement = iconElement?.querySelector("title");
      expect(titleElement?.textContent).toBeDefined();
    });

    /**
     * @description Handles all configured file types
     * @scenario Every file type from FILE_TYPE_ICONS
     * @expected Each renders without errors with correct attributes
     */
    it.each(
      Object.keys(FILE_TYPE_ICONS) as FileType[],
    )("should handle '$type' file type", (type) => {
      // Map type back to a sample filename
      const sampleFiles: Record<FileType, string> = {
        image: "photo.jpg",
        video: "movie.mp4",
        audio: "song.mp3",
        document: "report.pdf",
        archive: "archive.zip",
        code: "script.ts",
        unknown: "file.exe",
      };

      const filename = sampleFiles[type];

      expect(() => render(<FileIcon filename={filename} />)).not.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  //  Edge cases
  // ---------------------------------------------------------------------------
  /**
   * Edge cases - boundary values and special inputs
   */
  describe("edge cases", () => {
    /**
     * @description Handles empty filename
     * @scenario filename is empty string
     * @expected Renders with "unknown" type
     */
    it("should handle empty filename", () => {
      const { container } = render(<FileIcon filename="" />);
      expect(container.firstChild).toHaveClass("file-icon--unknown");
    });

    /**
     * @description Handles filename without extension
     * @scenario filename has no dot separator
     * @expected Renders with "unknown" type
     */
    it("should handle filename without extension", () => {
      const { container } = render(<FileIcon filename="README" />);
      expect(container.firstChild).toHaveClass("file-icon--unknown");
    });

    /**
     * @description Handles filename with multiple dots
     * @scenario filename contains multiple dot separators
     * @expected Uses last extension for type detection
     */
    it("should handle filename with multiple dots", () => {
      const { container } = render(<FileIcon filename="archive.tar.gz" />);
      expect(container.firstChild).toHaveClass("file-icon--archive");
    });

    /**
     * @description Handles case-insensitive extensions
     * @scenario Extension has uppercase letters
     * @expected Correct type detected regardless of case
     */
    it.each([
      { filename: "FILE.JPG", expectedClass: "file-icon--image" },
      { filename: "document.PDF", expectedClass: "file-icon--document" },
      { filename: "SCRIPT.TS", expectedClass: "file-icon--code" },
    ])("should handle uppercase extension: '$filename'", ({
      filename,
      expectedClass,
    }) => {
      const { container } = render(<FileIcon filename={filename} />);
      expect(container.firstChild).toHaveClass(expectedClass);
    });

    /**
     * @description Handles very long filenames
     * @scenario filename exceeds typical length
     * @expected Component renders without errors
     */
    it("should handle very long filename", () => {
      const longFilename = `${"a".repeat(255)}.pdf`;
      expect(() => render(<FileIcon filename={longFilename} />)).not.toThrow();
    });

    /**
     * @description Handles special characters in filename
     * @scenario filename contains unicode or special chars
     * @expected Component renders without errors
     */
    it.each([
      { filename: "файл.рус.pdf" },
      { filename: "file@#$%.txt" },
      { filename: "file with spaces.doc" },
    ])("should handle special characters: '$filename'", ({ filename }) => {
      expect(() => render(<FileIcon filename={filename} />)).not.toThrow();
    });
  });
});
