import { render, screen } from "@testing-library/react";
import type { Mock } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { FileUploadDropzone } from "@/features/file/file-upload";

import { FileManagerDropzone } from "../FileManagerDropzone";

vi.mock("@/features/file/file-upload", () => ({
  FileUploadDropzone: vi.fn(() => <div data-testid="file-upload-dropzone" />),
}));

describe("FileManagerDropzone", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("when isVisible is true", () => {
    /**
     * @description Renders the dropzone wrapper and FileUploadDropzone component
     * @scenario isVisible prop is true
     * @expected Component renders div with class "file-manager__dropzone" and FileUploadDropzone inside
     */
    it("should render dropzone container with FileUploadDropzone", () => {
      // Arrange
      // Act
      const { container } = render(<FileManagerDropzone isVisible={true} />);

      // Assert
      const dropzoneDiv = container.querySelector(".file-manager__dropzone");
      expect(dropzoneDiv).toBeInTheDocument();
      expect(screen.getByTestId("file-upload-dropzone")).toBeInTheDocument();
    });

    /**
     * @description Passes correct props to FileUploadDropzone
     * @scenario isVisible is true
     * @expected FileUploadDropzone is called with mode="local", clickable=true, multiple=true, comment="Загружено через FileManager"
     */
    it("should pass correct props to FileUploadDropzone", () => {
      // Arrange
      // Act
      render(<FileManagerDropzone isVisible={true} />);

      // Assert
      expect(FileUploadDropzone).toHaveBeenCalledTimes(1);
      const callArgs = (FileUploadDropzone as Mock).mock.calls[0][0];
      expect(callArgs.mode).toBe("local");
      expect(callArgs.clickable).toBe(true);
      expect(callArgs.multiple).toBe(true);
      expect(callArgs.comment).toBe("Загружено через FileManager");
    });
  });

  describe("when isVisible is false", () => {
    /**
     * @description Returns null when isVisible is false
     * @scenario isVisible prop is false
     * @expected Component renders nothing (null)
     */
    it("should return null and not render any content", () => {
      // Arrange
      // Act
      const { container } = render(<FileManagerDropzone isVisible={false} />);

      // Assert
      expect(container.firstChild).toBeNull();
      expect(
        container.querySelector(".file-manager__dropzone"),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByTestId("file-upload-dropzone"),
      ).not.toBeInTheDocument();
      expect(FileUploadDropzone).not.toHaveBeenCalled();
    });
  });
});
