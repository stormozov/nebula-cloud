import { beforeEach, describe, expect, it } from "vitest";
import {
  addFile,
  clearError,
  fileSlice,
  removeFile,
  resetState,
  setError,
  setFileList,
  setLoading,
  setSelectedFile,
  setUploading,
  setUploadProgress,
  updateFile,
} from "./slice";
import type { IFile, IFileState } from "./types";

// =============================================================================
// HELPERS AND MOCKS
// =============================================================================

/**
 * Creates a mock file for testing
 *
 * @param id - File identifier
 * @param originalName - File name
 * @returns Mock IFile object
 */
const createMockFile = (id: number, originalName: string): IFile => ({
  id,
  originalName,
  size: 1024,
  comment: "",
  sizeFormatted: "1 KB",
  uploadedAt: new Date().toISOString(),
  lastDownloaded: null,
  hasPublicLink: false,
  publicLinkUrl: null,
  downloadUrl: "",
});

/**
 * Creates a deep copy of initial state for testing
 *
 * @returns Fresh initial state object
 */
const getInitialState = (): IFileState => ({
  fileList: [],
  selectedFile: null,
  isLoading: false,
  isUploading: false,
  uploadProgress: 0,
  error: null,
});

const mockFileList = [
  createMockFile(1, "file1.txt"),
  createMockFile(2, "file2.txt"),
  createMockFile(999, "nonexistent.txt"),
];

// =============================================================================
// TEST SUITE
// =============================================================================

describe("fileSlice", () => {
  let initialState: IFileState;

  beforeEach(() => {
    initialState = getInitialState();
  });

  // ---------------------------------------------------------------------------
  // Initial State Tests
  // ---------------------------------------------------------------------------

  describe("Initial State", () => {
    /**
     * @description Should have correct initial state structure
     * @scenario File slice is initialized without any actions
     * @expected All state properties have correct default values
     */
    it("should have correct initial state structure", () => {
      const state = fileSlice.reducer(undefined, { type: "@@INIT" });

      expect(state.fileList).toEqual([]);
      expect(state.selectedFile).toBeNull();
      expect(state.isLoading).toBe(false);
      expect(state.isUploading).toBe(false);
      expect(state.uploadProgress).toBe(0);
      expect(state.error).toBeNull();
    });

    /**
     * @description Should return initial state for unknown actions
     * @scenario Reducer receives unhandled action type
     * @expected State remains unchanged
     */
    it("should return initial state for unknown actions", () => {
      const state = fileSlice.reducer(initialState, { type: "UNKNOWN_ACTION" });

      expect(state).toEqual(initialState);
    });
  });

  // ---------------------------------------------------------------------------
  // setFileList Tests
  // ---------------------------------------------------------------------------

  describe("setFileList", () => {
    /**
     * @description Should set file list correctly
     * @scenario setFileList action dispatched with array of files
     * @expected fileList contains provided files, error is cleared
     */
    it("should set file list correctly", () => {
      const files = mockFileList;
      const state = fileSlice.reducer(initialState, setFileList(files));

      expect(state.fileList).toEqual(files);
      expect(state.error).toBeNull();
    });

    /**
     * @description Should clear error when setting file list
     * @scenario setFileList dispatched when error exists
     * @expected error is set to null after action
     */
    it("should clear error when setting file list", () => {
      const stateWithError: IFileState = {
        ...initialState,
        error: "Previous error",
      };

      const files = [mockFileList[0]];
      const state = fileSlice.reducer(stateWithError, setFileList(files));

      expect(state.fileList).toEqual(files);
      expect(state.error).toBeNull();
    });

    /**
     * @description Should handle empty file list
     * @scenario setFileList dispatched with empty array
     * @expected fileList is empty array
     */
    it("should handle empty file list", () => {
      const state = fileSlice.reducer(initialState, setFileList([]));

      expect(state.fileList).toEqual([]);
      expect(state.fileList.length).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // setSelectedFile Tests
  // ---------------------------------------------------------------------------

  describe("setSelectedFile", () => {
    /**
     * @description Should set selected file correctly
     * @scenario setSelectedFile dispatched with file object
     * @expected selectedFile matches provided file
     */
    it("should set selected file correctly", () => {
      const file = mockFileList[0];
      const state = fileSlice.reducer(initialState, setSelectedFile(file));

      expect(state.selectedFile).toEqual(file);
    });

    /**
     * @description Should set selected file to null
     * @scenario setSelectedFile dispatched with null
     * @expected selectedFile is null
     */
    it("should set selected file to null", () => {
      const stateWithFile: IFileState = {
        ...initialState,
        selectedFile: mockFileList[0],
      };

      const state = fileSlice.reducer(stateWithFile, setSelectedFile(null));

      expect(state.selectedFile).toBeNull();
    });

    /**
     * @description Should not affect other state properties
     * @scenario setSelectedFile dispatched
     * @expected Only selectedFile changes, other properties remain unchanged
     */
    it("should not affect other state properties", () => {
      const file = mockFileList[0];
      const stateWithLoading: IFileState = {
        ...initialState,
        isLoading: true,
        isUploading: true,
        uploadProgress: 50,
      };

      const state = fileSlice.reducer(stateWithLoading, setSelectedFile(file));

      expect(state.selectedFile).toEqual(file);
      expect(state.isLoading).toBe(true);
      expect(state.isUploading).toBe(true);
      expect(state.uploadProgress).toBe(50);
    });
  });

  // ---------------------------------------------------------------------------
  // addFile Tests
  // ---------------------------------------------------------------------------

  describe("addFile", () => {
    /**
     * @description Should add file to beginning of list
     * @scenario addFile dispatched with new file
     * @expected New file is at index 0 of fileList
     */
    it("should add file to beginning of list", () => {
      const existingFile = mockFileList[0];
      const newFile = mockFileList[1];
      const stateWithFiles: IFileState = {
        ...initialState,
        fileList: [existingFile],
      };

      const state = fileSlice.reducer(stateWithFiles, addFile(newFile));

      expect(state.fileList[0]).toEqual(newFile);
      expect(state.fileList[1]).toEqual(existingFile);
      expect(state.fileList.length).toBe(2);
    });

    /**
     * @description Should clear error when adding file
     * @scenario addFile dispatched when error exists
     * @expected error is set to null after action
     */
    it("should clear error when adding file", () => {
      const stateWithError: IFileState = {
        ...initialState,
        error: "Upload error",
      };

      const file = mockFileList[0];
      const state = fileSlice.reducer(stateWithError, addFile(file));

      expect(state.fileList).toContainEqual(file);
      expect(state.error).toBeNull();
    });

    /**
     * @description Should add file to empty list
     * @scenario addFile dispatched with empty fileList
     * @expected fileList contains only the new file
     */
    it("should add file to empty list", () => {
      const file = mockFileList[0];
      const state = fileSlice.reducer(initialState, addFile(file));

      expect(state.fileList).toEqual([file]);
      expect(state.fileList.length).toBe(1);
    });
  });

  // ---------------------------------------------------------------------------
  // updateFile Tests
  // ---------------------------------------------------------------------------

  describe("updateFile", () => {
    /**
     * @description Should update existing file in list
     * @scenario updateFile dispatched with updated file data
     * @expected File at matching ID is replaced with new data
     */
    it("should update existing file in list", () => {
      const originalFile = mockFileList[0];
      const updatedFile = { ...originalFile, originalName: "updated.txt" };
      const stateWithFiles: IFileState = {
        ...initialState,
        fileList: [originalFile],
      };

      const state = fileSlice.reducer(stateWithFiles, updateFile(updatedFile));

      expect(state.fileList[0].originalName).toBe("updated.txt");
      expect(state.fileList[0].id).toBe(1);
    });

    /**
     * @description Should update selected file if IDs match
     * @scenario updateFile dispatched for currently selected file
     * @expected Both fileList and selectedFile are updated
     */
    it("should update selected file if IDs match", () => {
      const originalFile = mockFileList[0];
      const updatedFileName = "updated.txt";
      const updatedFile = { ...originalFile, originalName: updatedFileName };
      const stateWithSelection: IFileState = {
        ...initialState,
        fileList: [originalFile],
        selectedFile: originalFile,
      };

      const state = fileSlice.reducer(
        stateWithSelection,
        updateFile(updatedFile),
      );

      expect(state.fileList[0].originalName).toBe(updatedFileName);
      expect(state.selectedFile?.originalName).toBe(updatedFileName);
    });

    /**
     * @description Should not update if file ID not found
     * @scenario updateFile dispatched with non-existent ID
     * @expected State remains unchanged
     */
    it("should not update if file ID not found", () => {
      const existingFile = mockFileList[0];
      const nonExistentFile = mockFileList[2];
      const stateWithFiles: IFileState = {
        ...initialState,
        fileList: [existingFile],
      };

      const state = fileSlice.reducer(
        stateWithFiles,
        updateFile(nonExistentFile),
      );

      expect(state.fileList).toEqual([existingFile]);
    });

    /**
     * @description Should clear error when updating file
     * @scenario updateFile dispatched when error exists
     * @expected error is set to null after action
     */
    it("should clear error when updating file", () => {
      const stateWithError: IFileState = {
        ...initialState,
        fileList: [mockFileList[0]],
        error: "Update error",
      };

      const updatedFile = createMockFile(1, "updated.txt");
      const state = fileSlice.reducer(stateWithError, updateFile(updatedFile));

      expect(state.error).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // removeFile Tests
  // ---------------------------------------------------------------------------

  describe("removeFile", () => {
    /**
     * @description Should remove file from list by ID
     * @scenario removeFile dispatched with existing file ID
     * @expected File is removed from fileList
     */
    it("should remove file from list by ID", () => {
      const [file1, file2] = mockFileList;
      const stateWithFiles: IFileState = {
        ...initialState,
        fileList: [file1, file2],
      };

      const state = fileSlice.reducer(stateWithFiles, removeFile(1));

      expect(state.fileList).toEqual([file2]);
      expect(state.fileList.length).toBe(1);
    });

    /**
     * @description Should clear selected file if removed file was selected
     * @scenario removeFile dispatched for currently selected file
     * @expected selectedFile is set to null
     */
    it("should clear selected file if removed file was selected", () => {
      const file = mockFileList[0];
      const stateWithSelection: IFileState = {
        ...initialState,
        fileList: [file],
        selectedFile: file,
      };

      const state = fileSlice.reducer(stateWithSelection, removeFile(1));

      expect(state.fileList).toEqual([]);
      expect(state.selectedFile).toBeNull();
    });

    /**
     * @description Should keep selected file if different file removed
     * @scenario removeFile dispatched for non-selected file
     * @expected selectedFile remains unchanged
     */
    it("should keep selected file if different file removed", () => {
      const [file1, file2] = mockFileList;
      const stateWithSelection: IFileState = {
        ...initialState,
        fileList: [file1, file2],
        selectedFile: file2,
      };

      const state = fileSlice.reducer(stateWithSelection, removeFile(1));

      expect(state.fileList).toEqual([file2]);
      expect(state.selectedFile).toEqual(file2);
    });

    /**
     * @description Should clear error when removing file
     * @scenario removeFile dispatched when error exists
     * @expected error is set to null after action
     */
    it("should clear error when removing file", () => {
      const stateWithError: IFileState = {
        ...initialState,
        fileList: [mockFileList[0]],
        error: "Delete error",
      };

      const state = fileSlice.reducer(stateWithError, removeFile(1));

      expect(state.error).toBeNull();
    });

    /**
     * @description Should handle removing non-existent file
     * @scenario removeFile dispatched with ID not in list
     * @expected State remains unchanged
     */
    it("should handle removing non-existent file", () => {
      const file = mockFileList[0];
      const stateWithFiles: IFileState = { ...initialState, fileList: [file] };

      const state = fileSlice.reducer(stateWithFiles, removeFile(999));

      expect(state.fileList).toEqual([file]);
    });
  });

  // ---------------------------------------------------------------------------
  // setLoading Tests
  // ---------------------------------------------------------------------------

  describe("setLoading", () => {
    /**
     * @description Should set loading state to true
     * @scenario setLoading dispatched with true
     * @expected isLoading is true
     */
    it("should set loading state to true", () => {
      const state = fileSlice.reducer(initialState, setLoading(true));
      expect(state.isLoading).toBe(true);
    });

    /**
     * @description Should set loading state to false
     * @scenario setLoading dispatched with false
     * @expected isLoading is false
     */
    it("should set loading state to false", () => {
      const stateWithLoading: IFileState = { ...initialState, isLoading: true };
      const state = fileSlice.reducer(stateWithLoading, setLoading(false));
      expect(state.isLoading).toBe(false);
    });

    /**
     * @description Should not affect other state properties
     * @scenario setLoading dispatched
     * @expected Only isLoading changes
     */
    it("should not affect other state properties", () => {
      const state = fileSlice.reducer(initialState, setLoading(true));

      expect(state.isLoading).toBe(true);
      expect(state.isUploading).toBe(false);
      expect(state.uploadProgress).toBe(0);
      expect(state.error).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // setUploading Tests
  // ---------------------------------------------------------------------------

  describe("setUploading", () => {
    /**
     * @description Should set uploading state to true
     * @scenario setUploading dispatched with true
     * @expected isUploading is true
     */
    it("should set uploading state to true", () => {
      const state = fileSlice.reducer(initialState, setUploading(true));
      expect(state.isUploading).toBe(true);
    });

    /**
     * @description Should set uploading state to false
     * @scenario setUploading dispatched with false
     * @expected isUploading is false
     */
    it("should set uploading state to false", () => {
      const stateWithUploading: IFileState = {
        ...initialState,
        isUploading: true,
      };

      const state = fileSlice.reducer(stateWithUploading, setUploading(false));

      expect(state.isUploading).toBe(false);
    });

    /**
     * @description Should not affect other state properties
     * @scenario setUploading dispatched
     * @expected Only isUploading changes
     */
    it("should not affect other state properties", () => {
      const state = fileSlice.reducer(initialState, setUploading(true));

      expect(state.isUploading).toBe(true);
      expect(state.isLoading).toBe(false);
      expect(state.uploadProgress).toBe(0);
      expect(state.error).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // setUploadProgress Tests
  // ---------------------------------------------------------------------------

  describe("setUploadProgress", () => {
    /**
     * @description Should set upload progress percentage
     * @scenario setUploadProgress dispatched with number
     * @expected uploadProgress matches provided value
     */
    it("should set upload progress percentage", () => {
      const state = fileSlice.reducer(initialState, setUploadProgress(75));
      expect(state.uploadProgress).toBe(75);
    });

    /**
     * @description Should handle zero progress
     * @scenario setUploadProgress dispatched with 0
     * @expected uploadProgress is 0
     */
    it("should handle zero progress", () => {
      const stateWithProgress: IFileState = {
        ...initialState,
        uploadProgress: 50,
      };

      const state = fileSlice.reducer(stateWithProgress, setUploadProgress(0));

      expect(state.uploadProgress).toBe(0);
    });

    /**
     * @description Should handle 100 percent progress
     * @scenario setUploadProgress dispatched with 100
     * @expected uploadProgress is 100
     */
    it("should handle 100 percent progress", () => {
      const state = fileSlice.reducer(initialState, setUploadProgress(100));
      expect(state.uploadProgress).toBe(100);
    });

    /**
     * @description Should not affect other state properties
     * @scenario setUploadProgress dispatched
     * @expected Only uploadProgress changes
     */
    it("should not affect other state properties", () => {
      const state = fileSlice.reducer(initialState, setUploadProgress(50));

      expect(state.uploadProgress).toBe(50);
      expect(state.isLoading).toBe(false);
      expect(state.isUploading).toBe(false);
      expect(state.error).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // setError Tests
  // ---------------------------------------------------------------------------

  describe("setError", () => {
    /**
     * @description Should set error message
     * @scenario setError dispatched with string message
     * @expected error contains provided message
     */
    it("should set error message", () => {
      const errorMessage = "Something went wrong";
      const state = fileSlice.reducer(initialState, setError(errorMessage));
      expect(state.error).toBe(errorMessage);
    });

    /**
     * @description Should clear error when null passed
     * @scenario setError dispatched with null
     * @expected error is null
     */
    it("should clear error when null passed", () => {
      const stateWithError: IFileState = {
        ...initialState,
        error: "Existing error",
      };

      const state = fileSlice.reducer(stateWithError, setError(null));

      expect(state.error).toBeNull();
    });

    /**
     * @description Should reset loading state when error set
     * @scenario setError dispatched when isLoading is true
     * @expected isLoading is set to false
     */
    it("should reset loading state when error set", () => {
      const stateWithLoading: IFileState = { ...initialState, isLoading: true };

      const state = fileSlice.reducer(stateWithLoading, setError("Error"));

      expect(state.error).toBe("Error");
      expect(state.isLoading).toBe(false);
    });

    /**
     * @description Should reset uploading state when error set
     * @scenario setError dispatched when isUploading is true
     * @expected isUploading is set to false
     */
    it("should reset uploading state when error set", () => {
      const stateWithUploading: IFileState = {
        ...initialState,
        isUploading: true,
      };

      const state = fileSlice.reducer(stateWithUploading, setError("Error"));

      expect(state.error).toBe("Error");
      expect(state.isUploading).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // clearError Tests
  // ---------------------------------------------------------------------------

  describe("clearError", () => {
    /**
     * @description Should clear error message
     * @scenario clearError dispatched when error exists
     * @expected error is null
     */
    it("should clear error message", () => {
      const stateWithError: IFileState = {
        ...initialState,
        error: "Existing error",
      };

      const state = fileSlice.reducer(stateWithError, clearError());

      expect(state.error).toBeNull();
    });

    /**
     * @description Should not affect other state properties
     * @scenario clearError dispatched
     * @expected Only error changes, other properties remain unchanged
     */
    it("should not affect other state properties", () => {
      const stateWithMultiple: IFileState = {
        ...initialState,
        error: "Error",
        isLoading: true,
        isUploading: true,
        uploadProgress: 50,
      };

      const state = fileSlice.reducer(stateWithMultiple, clearError());

      expect(state.error).toBeNull();
      expect(state.isLoading).toBe(true);
      expect(state.isUploading).toBe(true);
      expect(state.uploadProgress).toBe(50);
    });

    /**
     * @description Should handle clearing when no error exists
     * @scenario clearError dispatched when error is already null
     * @expected State remains unchanged
     */
    it("should handle clearing when no error exists", () => {
      const state = fileSlice.reducer(initialState, clearError());
      expect(state.error).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // resetState Tests
  // ---------------------------------------------------------------------------

  describe("resetState", () => {
    /**
     * @description Should reset all state to initial values
     * @scenario resetState dispatched with modified state
     * @expected All properties match initial state
     */
    it("should reset all state to initial values", () => {
      const file = mockFileList[0];
      const modifiedState: IFileState = {
        fileList: [file],
        selectedFile: file,
        isLoading: true,
        isUploading: true,
        uploadProgress: 75,
        error: "Error",
      };

      const state = fileSlice.reducer(modifiedState, resetState());

      expect(state.fileList).toEqual([]);
      expect(state.selectedFile).toBeNull();
      expect(state.isLoading).toBe(false);
      expect(state.isUploading).toBe(false);
      expect(state.uploadProgress).toBe(0);
      expect(state.error).toBeNull();
    });

    /**
     * @description Should match initial state exactly
     * @scenario resetState dispatched
     * @expected State equals getInitialState()
     */
    it("should match initial state exactly", () => {
      const file = mockFileList[0];
      const modifiedState: IFileState = {
        fileList: [file],
        selectedFile: file,
        isLoading: true,
        isUploading: true,
        uploadProgress: 75,
        error: "Error",
      };

      const state = fileSlice.reducer(modifiedState, resetState());
      const expectedState = getInitialState();

      expect(state).toEqual(expectedState);
    });
  });
});
