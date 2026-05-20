import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import type { IFile } from "@/entities/file";

import { useFileManagerModals } from "../useFileManagerModals";

// =============================================================================
// TEST HELPERS
// =============================================================================

const createMockFile = (overrides?: Partial<IFile>): IFile => ({
  id: 1,
  originalName: "test.jpg",
  comment: "test comment",
  size: 1024,
  sizeFormatted: "1 KB",
  uploadedAt: "2025-01-01T00:00:00Z",
  lastDownloaded: null,
  hasPublicLink: false,
  publicLinkUrl: null,
  downloadUrl: "https://example.com/download/1",
  ...overrides,
});

// =============================================================================
// TESTS
// =============================================================================

describe("useFileManagerModals", () => {
  beforeEach(() => {
    // No global mocks needed – pure hook
  });

  describe("initial state", () => {
    /**
     * @description Should have all modals closed and no selected files on initial render
     * @scenario Hook is called without any actions
     * @expected modalOpen all false, selectedFile null, selectedImageFile null
     */
    it("should initialize with all modals closed and no files selected", () => {
      // Arrange
      const { result } = renderHook(() => useFileManagerModals());

      // Assert
      expect(result.current.modalOpen).toEqual({
        delete: false,
        rename: false,
        comment: false,
        link: false,
        imageViewer: false,
      });
      expect(result.current.selectedFile).toBeNull();
      expect(result.current.selectedImageFile).toBeNull();
    });
  });

  describe("openModal", () => {
    /**
     * @description Should set selectedFile and open the specified modal
     * @scenario User calls openModal with 'delete' type and a file
     * @expected selectedFile equals the provided file, modalOpen.delete becomes true, other modals remain false
     */
    it("should open delete modal and set selected file", () => {
      // Arrange
      const { result } = renderHook(() => useFileManagerModals());
      const file = createMockFile({ id: 1, originalName: "doc.pdf" });

      // Act
      act(() => {
        result.current.openModal("delete", file);
      });

      // Assert
      expect(result.current.selectedFile).toEqual(file);
      expect(result.current.modalOpen.delete).toBe(true);
      expect(result.current.modalOpen.rename).toBe(false);
      expect(result.current.modalOpen.comment).toBe(false);
      expect(result.current.modalOpen.link).toBe(false);
      expect(result.current.modalOpen.imageViewer).toBe(false);
    });

    /**
     * @description Should update selected file and open new modal without closing previously opened modals
     * @scenario User opens rename modal with file1, then comment modal with file2
     * @expected selectedFile updates to file2, new modal opens, previous modal remains open
     */
    it("should update selected file and open different modal when called multiple times", () => {
      // Arrange
      const { result } = renderHook(() => useFileManagerModals());
      const file1 = createMockFile({ id: 1 });
      const file2 = createMockFile({ id: 2 });

      // Act
      act(() => {
        result.current.openModal("rename", file1);
      });
      act(() => {
        result.current.openModal("comment", file2);
      });

      // Assert
      expect(result.current.selectedFile).toEqual(file2);
      expect(result.current.modalOpen.rename).toBe(true); // remains open
      expect(result.current.modalOpen.comment).toBe(true);
    });
  });

  describe("closeModal", () => {
    /**
     * @description Should close the specified modal and clear selectedFile when modal is not imageViewer
     * @scenario User opens delete modal with a file, then closes it
     * @expected modalOpen.delete becomes false, selectedFile becomes null
     */
    it("should close modal and clear selectedFile for non-imageViewer modals", () => {
      // Arrange
      const { result } = renderHook(() => useFileManagerModals());
      const file = createMockFile();

      // Act
      act(() => {
        result.current.openModal("delete", file);
      });
      act(() => {
        result.current.closeModal("delete");
      });

      // Assert
      expect(result.current.modalOpen.delete).toBe(false);
      expect(result.current.selectedFile).toBeNull();
    });

    /**
     * @description Should close imageViewer modal but keep selectedFile unchanged
     * @scenario User opens imageViewer modal with a file, then closes it
     * @expected modalOpen.imageViewer becomes false, selectedFile remains the file
     */
    it("should close imageViewer modal without clearing selectedFile", () => {
      // Arrange
      const { result } = renderHook(() => useFileManagerModals());
      const file = createMockFile();

      // Act
      act(() => {
        result.current.openModal("imageViewer", file);
      });
      act(() => {
        result.current.closeModal("imageViewer");
      });

      // Assert
      expect(result.current.modalOpen.imageViewer).toBe(false);
      expect(result.current.selectedFile).toEqual(file);
    });

    /**
     * @description Should close the specified modal, clear selectedFile (unless imageViewer), and leave other modals unchanged
     * @scenario User opens rename modal with a file, then closes a different (delete) modal
     * @expected delete modal remains false, rename modal stays open, but selectedFile becomes null because closeModal clears it for non-imageViewer
     */
    it("should close only the specified modal and leave others unchanged", () => {
      // Arrange
      const { result } = renderHook(() => useFileManagerModals());
      const file = createMockFile();

      // Act
      act(() => {
        result.current.openModal("rename", file);
      });
      act(() => {
        result.current.closeModal("delete");
      });

      // Assert
      expect(result.current.modalOpen.rename).toBe(true);
      expect(result.current.modalOpen.delete).toBe(false);
      expect(result.current.selectedFile).toBeNull(); // cleared because closeModal called with non-imageViewer type
    });
  });

  describe("updateSelectedFile", () => {
    /**
     * @description Should update selectedFile without affecting modal states
     * @scenario User calls updateSelectedFile with a new file
     * @expected selectedFile updates, all modals remain closed
     */
    it("should set selectedFile without opening any modal", () => {
      // Arrange
      const { result } = renderHook(() => useFileManagerModals());
      const file = createMockFile();

      // Act
      act(() => {
        result.current.updateSelectedFile(file);
      });

      // Assert
      expect(result.current.selectedFile).toEqual(file);
      expect(result.current.modalOpen).toEqual({
        delete: false,
        rename: false,
        comment: false,
        link: false,
        imageViewer: false,
      });
    });

    /**
     * @description Should allow clearing selectedFile by passing null
     * @scenario User calls updateSelectedFile with null
     * @expected selectedFile becomes null
     */
    it("should clear selectedFile when null is passed", () => {
      // Arrange
      const { result } = renderHook(() => useFileManagerModals());
      const file = createMockFile();

      // Act
      act(() => {
        result.current.updateSelectedFile(file);
      });
      act(() => {
        result.current.updateSelectedFile(null);
      });

      // Assert
      expect(result.current.selectedFile).toBeNull();
    });
  });

  describe("setSelectedImageFile", () => {
    /**
     * @description Should update selectedImageFile independently of selectedFile
     * @scenario User calls setSelectedImageFile with an image file
     * @expected selectedImageFile updates, selectedFile and modals unaffected
     */
    it("should set selectedImageFile without affecting other state", () => {
      // Arrange
      const { result } = renderHook(() => useFileManagerModals());
      const imageFile = createMockFile({ id: 5, originalName: "photo.png" });

      // Act
      act(() => {
        result.current.setSelectedImageFile(imageFile);
      });

      // Assert
      expect(result.current.selectedImageFile).toEqual(imageFile);
      expect(result.current.selectedFile).toBeNull();
      expect(result.current.modalOpen).toEqual({
        delete: false,
        rename: false,
        comment: false,
        link: false,
        imageViewer: false,
      });
    });

    /**
     * @description Should allow clearing selectedImageFile by passing null
     * @scenario User calls setSelectedImageFile with null
     * @expected selectedImageFile becomes null
     */
    it("should clear selectedImageFile when null is passed", () => {
      // Arrange
      const { result } = renderHook(() => useFileManagerModals());
      const imageFile = createMockFile();

      // Act
      act(() => {
        result.current.setSelectedImageFile(imageFile);
      });
      act(() => {
        result.current.setSelectedImageFile(null);
      });

      // Assert
      expect(result.current.selectedImageFile).toBeNull();
    });
  });

  describe("interaction between modal open/close and selection state", () => {
    /**
     * @description Should not affect selectedImageFile when opening/closing regular modals
     * @scenario User opens delete modal, then closes it, with selectedImageFile already set
     * @expected selectedImageFile remains unchanged
     */
    it("should preserve selectedImageFile when opening and closing non-image modals", () => {
      // Arrange
      const { result } = renderHook(() => useFileManagerModals());
      const file = createMockFile({ id: 1 });
      const imageFile = createMockFile({ id: 2 });

      // Act
      act(() => {
        result.current.setSelectedImageFile(imageFile);
      });
      act(() => {
        result.current.openModal("rename", file);
      });
      act(() => {
        result.current.closeModal("rename");
      });

      // Assert
      expect(result.current.selectedImageFile).toEqual(imageFile);
      expect(result.current.selectedFile).toBeNull();
    });

    /**
     * @description Should not affect selectedFile when setting selectedImageFile
     * @scenario User sets selectedImageFile, then opens a modal
     * @expected both files independent
     */
    it("should keep selectedFile and selectedImageFile independent", () => {
      // Arrange
      const { result } = renderHook(() => useFileManagerModals());
      const docFile = createMockFile({ id: 10 });
      const imgFile = createMockFile({ id: 20 });

      // Act
      act(() => {
        result.current.updateSelectedFile(docFile);
      });
      act(() => {
        result.current.setSelectedImageFile(imgFile);
      });

      // Assert
      expect(result.current.selectedFile).toEqual(docFile);
      expect(result.current.selectedImageFile).toEqual(imgFile);
    });
  });
});
