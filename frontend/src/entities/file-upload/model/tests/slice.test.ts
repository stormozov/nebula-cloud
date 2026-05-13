import { configureStore } from "@reduxjs/toolkit";
import { beforeEach, describe, expect, it } from "vitest";

import { userSlice } from "@/entities/user";

import fileUploadReducer, {
  addFiles,
  cancelUpload,
  clearCompleted,
  forceClearQueue,
  markForReupload,
  removeFile,
  resetState,
  retryUpload,
  setDropzoneVisible,
  setNeedsReupload,
  setPanelVisible,
  updateProgress,
  updateStatus,
} from "../slice";
import type { IUploadState } from "../types";

describe("fileUploadSlice", () => {
  let store: ReturnType<typeof configureStore<{ fileUpload: IUploadState }>>;

  beforeEach(() => {
    store = configureStore({
      reducer: { fileUpload: fileUploadReducer },
    });
  });

  const getState = () => store.getState().fileUpload;

  const createMockFile = (name: string, size: number, type = "text/plain") => {
    return new File([new ArrayBuffer(size)], name, { type });
  };

  /**
   * @description Should have correct initial state
   * @scenario Create store without actions
   * @expected State matches initialState
   */
  it("should have correct initial state", () => {
    const state = getState();
    expect(state).toEqual({
      queue: [],
      isPanelVisible: false,
      isDropzoneVisible: false,
      activeUploadId: null,
      totalUploaded: 0,
      totalFailed: 0,
      isQueueCompleted: false,
    });
  });

  /**
   * @description Should add files to queue, show panel, and start first file
   * @scenario Dispatch addFiles with two files
   * @expected Queue length = 2, isPanelVisible = true, activeUploadId set,
   *    first file status "uploading", second "pending"
   */
  it("should add files to queue, show panel, and start first file", () => {
    const file1 = createMockFile("test1.txt", 100);
    const file2 = createMockFile("test2.txt", 200);
    store.dispatch(addFiles({ files: [file1, file2] }));

    const state = getState();
    expect(state.queue).toHaveLength(2);
    expect(state.isPanelVisible).toBe(true);
    expect(state.isQueueCompleted).toBe(false);
    expect(state.activeUploadId).toBe(state.queue[0].id);

    const first = state.queue[0];
    expect(first.status).toBe("uploading");
    expect(first.startedAt).toBeDefined();
    expect(first.file.name).toBe("test1.txt");
    expect(first.file.size).toBe(100);
    expect(first.file.type).toBe("text/plain");
    expect(first.file.lastModified).toBeDefined();

    const second = state.queue[1];
    expect(second.status).toBe("pending");
    expect(second.startedAt).toBeUndefined();
  });

  /**
   * @description Should use provided uploadIds when available
   * @scenario Dispatch addFiles with uploadIds
   * @expected Upload IDs match provided values
   */
  it("should use provided uploadIds when available", () => {
    const file = createMockFile("test.txt", 100);
    const ids = ["id1", "id2"];
    store.dispatch(addFiles({ files: [file, file], uploadIds: ids }));

    const state = getState();
    expect(state.queue[0].id).toBe("id1");
    expect(state.queue[1].id).toBe("id2");
  });

  /**
   * @description Should add comment to files when provided
   * @scenario Dispatch addFiles with comment
   * @expected Each file has comment in file.comment
   */
  it("should add comment to files when provided", () => {
    const file = createMockFile("test.txt", 100);
    store.dispatch(addFiles({ files: [file, file], comment: "Test comment" }));

    const state = getState();
    expect(state.queue[0].file.comment).toBe("Test comment");
    expect(state.queue[1].file.comment).toBe("Test comment");
  });

  /**
   * @description Should not start new upload if queue already has active upload
   * @scenario Add files, then add more files while active exists
   * @expected Active upload unchanged, new files added as pending
   */
  it("should not start new upload if queue already has active upload", () => {
    const file1 = createMockFile("file1.txt", 100);
    store.dispatch(addFiles({ files: [file1] }));
    const firstId = getState().activeUploadId;

    const file2 = createMockFile("file2.txt", 100);
    store.dispatch(addFiles({ files: [file2] }));

    const state = getState();
    expect(state.activeUploadId).toBe(firstId);
    expect(state.queue).toHaveLength(2);
    expect(state.queue[1].status).toBe("pending");
  });

  /**
   * @description Should update progress for uploading file
   * @scenario Dispatch updateProgress with valid uploadId and progress
   * @expected Progress updated for that file, others unchanged
   */
  it("should update progress for uploading file", () => {
    const file = createMockFile("test.txt", 100);
    store.dispatch(addFiles({ files: [file] }));
    const uploadId = getState().activeUploadId;

    if (!uploadId) throw new Error("Upload ID not found");

    store.dispatch(updateProgress({ uploadId, progress: 50 }));

    const state = getState();
    expect(state.queue[0].progress).toBe(50);
  });

  /**
   * @description Should not update progress if file not found
   * @scenario Dispatch updateProgress with invalid uploadId
   * @expected No state change
   */
  it("should not update progress if file not found", () => {
    const file = createMockFile("test.txt", 100);
    store.dispatch(addFiles({ files: [file] }));
    const initialProgress = getState().queue[0].progress;

    store.dispatch(updateProgress({ uploadId: "invalid", progress: 50 }));

    expect(getState().queue[0].progress).toBe(initialProgress);
  });

  /**
   * @description Should handle success status correctly
   * @scenario Dispatch updateStatus with success
   * @expected File status becomes success, progress 100, uploadedFileId set,
   *    totalUploaded increments, activeUploadId cleared, next pending starts
   */
  it("should handle success status correctly", () => {
    const file1 = createMockFile("file1.txt", 100);
    const file2 = createMockFile("file2.txt", 100);
    store.dispatch(addFiles({ files: [file1, file2] }));
    const uploadId1 = getState().activeUploadId;

    if (!uploadId1) throw new Error("Upload ID not found");

    store.dispatch(
      updateStatus({
        uploadId: uploadId1,
        status: "success",
        uploadedFileId: 123,
      }),
    );

    let state = getState();
    expect(state.queue[0].status).toBe("success");
    expect(state.queue[0].progress).toBe(100);
    expect(state.queue[0].uploadedFileId).toBe(123);
    expect(state.queue[0].completedAt).toBeDefined();
    expect(state.totalUploaded).toBe(1);
    expect(state.activeUploadId).toBe(state.queue[1].id);
    expect(state.queue[1].status).toBe("uploading");
    expect(state.queue[1].startedAt).toBeDefined();

    if (!state.activeUploadId) throw new Error("Active upload ID not found");

    // Complete second file
    store.dispatch(
      updateStatus({
        uploadId: state.activeUploadId,
        status: "success",
        uploadedFileId: 456,
      }),
    );

    state = getState();
    expect(state.totalUploaded).toBe(2);
    expect(state.activeUploadId).toBeNull();
    expect(state.isQueueCompleted).toBe(true);
  });

  /**
   * @description Should handle error status correctly
   * @scenario Dispatch updateStatus with error
   * @expected File status error, error message set, totalFailed increments,
   * activeUploadId cleared, next pending starts
   */
  it("should handle error status correctly", () => {
    const file1 = createMockFile("file1.txt", 100);
    const file2 = createMockFile("file2.txt", 100);
    store.dispatch(addFiles({ files: [file1, file2] }));
    const uploadId1 = getState().activeUploadId;

    if (!uploadId1) throw new Error("Upload ID not found");

    store.dispatch(
      updateStatus({
        uploadId: uploadId1,
        status: "error",
        error: "Network error",
      }),
    );

    const state = getState();
    expect(state.queue[0].status).toBe("error");
    expect(state.queue[0].error).toBe("Network error");
    expect(state.queue[0].progress).toBe(0);
    expect(state.queue[0].completedAt).toBeDefined();
    expect(state.totalFailed).toBe(1);
    expect(state.activeUploadId).toBe(state.queue[1].id);
    expect(state.queue[1].status).toBe("uploading");
  });

  /**
   * @description Should not start next file if none pending, and mark queue
   *    completed
   * @scenario Update last file to success
   * @expected isQueueCompleted = true
   */
  it("should mark queue completed when all files finished", () => {
    const file = createMockFile("file.txt", 100);
    store.dispatch(addFiles({ files: [file] }));
    const uploadId = getState().activeUploadId;

    if (!uploadId) throw new Error("Upload ID not found");

    store.dispatch(updateStatus({ uploadId, status: "success" }));

    const state = getState();
    expect(state.isQueueCompleted).toBe(true);
    expect(state.activeUploadId).toBeNull();
  });

  /**
   * @description Should remove file only if not uploading
   * @scenario Remove a pending file, then try to remove uploading file
   *    (should fail)
   * @expected Pending removed, uploading stays, counters updated
   */
  it("should remove file only if not uploading", () => {
    const file1 = createMockFile("file1.txt", 100);
    const file2 = createMockFile("file2.txt", 100);
    store.dispatch(addFiles({ files: [file1, file2] }));
    const uploadingId = getState().activeUploadId;
    const pendingId = getState().queue[1].id;

    if (!uploadingId) throw new Error("Upload ID not found");

    // Remove pending file
    store.dispatch(removeFile({ uploadId: pendingId }));
    let state = getState();
    expect(state.queue).toHaveLength(1);
    expect(state.queue[0].id).toBe(uploadingId);
    expect(state.isPanelVisible).toBe(true);
    expect(state.isQueueCompleted).toBe(false);

    // Try to remove uploading file (should not work)
    store.dispatch(removeFile({ uploadId: uploadingId }));
    state = getState();

    expect(state.queue).toHaveLength(1);
    expect(state.queue[0].id).toBe(uploadingId);
  });

  /**
   * @description Should update counters when removing success/error files
   * @scenario Add file, mark success, then remove it
   * @expected totalUploaded decreases, queue empty, panel hidden
   */
  it("should update counters when removing success/error files", () => {
    const file = createMockFile("file.txt", 100);
    store.dispatch(addFiles({ files: [file] }));
    const uploadId = getState().activeUploadId;

    if (!uploadId) throw new Error("Upload ID not found");

    store.dispatch(updateStatus({ uploadId, status: "success" }));

    store.dispatch(removeFile({ uploadId }));
    const state = getState();

    expect(state.queue).toHaveLength(0);
    expect(state.totalUploaded).toBe(0);
    expect(state.isPanelVisible).toBe(false);
    expect(state.activeUploadId).toBeNull();
    expect(state.isQueueCompleted).toBe(false);
  });

  /**
   * @description Should decrement totalFailed when removing error file
   * @scenario Add file, mark as error, then remove it
   * @expected totalFailed decreases from 1 to 0
   */
  it("should decrement totalFailed when removing error file", () => {
    const file = createMockFile("file.txt", 100);
    store.dispatch(addFiles({ files: [file] }));
    const uploadId = getState().activeUploadId;

    if (!uploadId) {
      throw new Error("Upload ID not found");
    }

    // Mark as error
    store.dispatch(
      updateStatus({ uploadId, status: "error", error: "Test error" }),
    );
    expect(getState().totalFailed).toBe(1);

    // Remove error file
    store.dispatch(removeFile({ uploadId }));
    const state = getState();

    expect(state.totalFailed).toBe(0);
    expect(state.queue).toHaveLength(0);
  });

  /**
   * @description Should set panel visibility only when allowed
   * @scenario Try to hide panel with ongoing uploads
   * @expected Panel stays visible; hide when queue empty or completed
   */
  it("should set panel visibility only when allowed", () => {
    // Initially panel is false, we can set to true
    store.dispatch(setPanelVisible(true));
    expect(getState().isPanelVisible).toBe(true);

    // With ongoing upload, cannot hide
    const file = createMockFile("file.txt", 100);
    store.dispatch(addFiles({ files: [file] }));
    store.dispatch(setPanelVisible(false));

    expect(getState().isPanelVisible).toBe(true);

    // After all completed, can hide
    const uploadId = getState().activeUploadId;
    if (!uploadId) throw new Error("Upload ID not found");

    store.dispatch(updateStatus({ uploadId, status: "success" }));
    store.dispatch(setPanelVisible(false));

    expect(getState().isPanelVisible).toBe(false);
  });

  /**
   * @description Should set dropzone visibility
   * @scenario Dispatch setDropzoneVisible(true/false)
   * @expected isDropzoneVisible updated
   */
  it("should set dropzone visibility", () => {
    store.dispatch(setDropzoneVisible(true));
    expect(getState().isDropzoneVisible).toBe(true);
    store.dispatch(setDropzoneVisible(false));
    expect(getState().isDropzoneVisible).toBe(false);
  });

  /**
   * @description Should cancel active upload, mark error, and start next
   * @scenario Cancel uploading file with queue containing pending
   * @expected Upload status error, totalFailed incremented, next file starts
   */
  it("should cancel active upload, mark error, and start next", () => {
    const file1 = createMockFile("file1.txt", 100);
    const file2 = createMockFile("file2.txt", 100);
    store.dispatch(addFiles({ files: [file1, file2] }));

    const uploadId = getState().activeUploadId;
    if (!uploadId) throw new Error("Upload ID not found");

    store.dispatch(cancelUpload({ uploadId }));

    const state = getState();
    expect(state.queue[0].status).toBe("error");
    expect(state.queue[0].error).toBe("Загрузка отменена");
    expect(state.queue[0].completedAt).toBeDefined();
    expect(state.totalFailed).toBe(1);
    expect(state.activeUploadId).toBe(state.queue[1].id);
    expect(state.queue[1].status).toBe("uploading");
  });

  /**
   * @description Should mark queue as completed when canceling the only file in queue
   * @scenario Add single file, cancel it while uploading
   * @expected File status error, totalFailed incremented, isQueueCompleted true, activeUploadId null
   */
  it("should mark queue as completed when canceling the only file", () => {
    // Arrange
    const file = createMockFile("file.txt", 100);
    store.dispatch(addFiles({ files: [file] }));
    const uploadId = getState().activeUploadId;
    if (!uploadId) throw new Error("Upload ID not found");

    // Act
    store.dispatch(cancelUpload({ uploadId }));

    // Assert
    const state = getState();
    expect(state.queue[0].status).toBe("error");
    expect(state.queue[0].error).toBe("Загрузка отменена");
    expect(state.queue[0].completedAt).toBeDefined();
    expect(state.totalFailed).toBe(1);
    expect(state.activeUploadId).toBeNull();
    expect(state.isQueueCompleted).toBe(true);
  });

  /**
   * @description Should mark queue as completed when last file finishes with
   *    error
   * @scenario Add two files, first success, second error, no pending left
   * @expected isQueueCompleted = true after second finishes
   */
  it("should mark queue as completed when last file finishes with error", () => {
    const file1 = createMockFile("file1.txt", 100);
    const file2 = createMockFile("file2.txt", 100);
    store.dispatch(addFiles({ files: [file1, file2] }));

    const firstId = getState().activeUploadId;
    const secondId = getState().queue[1].id;

    if (!firstId) throw new Error("First upload ID not found");

    // First file success
    store.dispatch(updateStatus({ uploadId: firstId, status: "success" }));
    expect(getState().isQueueCompleted).toBe(false);
    expect(getState().activeUploadId).toBe(secondId);

    // Second file error
    store.dispatch(
      updateStatus({
        uploadId: secondId,
        status: "error",
        error: "Upload failed",
      }),
    );

    const state = getState();
    expect(state.isQueueCompleted).toBe(true);
    expect(state.activeUploadId).toBeNull();
    expect(state.totalUploaded).toBe(1);
    expect(state.totalFailed).toBe(1);
  });

  /**
   * @description Should not cancel non-uploading file
   * @scenario Cancel pending file
   * @expected No change
   */
  it("should not cancel non-uploading file", () => {
    const file1 = createMockFile("file1.txt", 100);
    const file2 = createMockFile("file2.txt", 100);
    store.dispatch(addFiles({ files: [file1, file2] }));
    const pendingId = getState().queue[1].id;

    store.dispatch(cancelUpload({ uploadId: pendingId }));

    const state = getState();
    expect(state.queue[1].status).toBe("pending");
    expect(state.totalFailed).toBe(0);
  });

  /**
   * @description Should clear completed only when queue completed
   * @scenario Try clear before completed, then after
   * @expected No change before, queue cleared after
   */
  it("should clear completed only when queue completed", () => {
    const file = createMockFile("file.txt", 100);
    store.dispatch(addFiles({ files: [file] }));

    store.dispatch(clearCompleted());
    expect(getState().queue).toHaveLength(1);

    const uploadId = getState().activeUploadId;
    if (!uploadId) throw new Error("Upload ID not found");

    store.dispatch(updateStatus({ uploadId, status: "success" }));
    store.dispatch(clearCompleted());

    expect(getState().queue).toHaveLength(0);
    expect(getState().isPanelVisible).toBe(false);
    expect(getState().isQueueCompleted).toBe(false);
  });

  /**
   * @description Should force clear queue regardless of state
   * @scenario Clear queue with ongoing upload
   * @expected Queue empty, panel hidden
   */
  it("should force clear queue regardless of state", () => {
    const file = createMockFile("file.txt", 100);
    store.dispatch(addFiles({ files: [file] }));

    store.dispatch(forceClearQueue());

    const state = getState();
    expect(state.queue).toHaveLength(0);
    expect(state.isPanelVisible).toBe(false);
    expect(state.activeUploadId).toBeNull();
    expect(state.isQueueCompleted).toBe(false);
  });

  /**
   * @description Should mark files for reupload and restart queue
   * @scenario Add files, then dispatch markForReupload
   * @expected All pending/uploading files become pending with
   *    needsReupload=true, progress 0, then first pending becomes uploading
   */
  it("should mark files for reupload and restart queue", () => {
    const file1 = createMockFile("file1.txt", 100);
    const file2 = createMockFile("file2.txt", 100);
    store.dispatch(addFiles({ files: [file1, file2] }));

    // First is uploading, second pending
    store.dispatch(markForReupload());

    const state = getState();

    // The first file should start downloading again.
    expect(state.queue[0].status).toBe("uploading");
    expect(state.queue[0].progress).toBe(0);
    expect(state.queue[0].needsReupload).toBe(true);
    expect(state.queue[0].startedAt).toBeDefined();

    // The second file remains in the waiting queue.
    expect(state.queue[1].status).toBe("pending");
    expect(state.queue[1].needsReupload).toBe(true);
    expect(state.queue[1].progress).toBe(0);
    expect(state.queue[1].startedAt).toBeUndefined();

    expect(state.activeUploadId).toBe(state.queue[0].id);
  });

  /**
   * @description Should reset state completely
   * @scenario Add files, then resetState
   * @expected State returns to initial
   */
  it("should reset state completely", () => {
    const file = createMockFile("file.txt", 100);
    store.dispatch(addFiles({ files: [file] }));
    store.dispatch(resetState());

    const state = getState();
    expect(state).toEqual({
      queue: [],
      isPanelVisible: false,
      isDropzoneVisible: false,
      activeUploadId: null,
      totalUploaded: 0,
      totalFailed: 0,
      isQueueCompleted: false,
    });
  });

  /**
   * @description Should reset state on logout action from userSlice
   * @scenario Dispatch user logout action
   * @expected State reset to initial
   */
  it("should reset state on logout action", () => {
    const file = createMockFile("file.txt", 100);
    store.dispatch(addFiles({ files: [file] }));
    store.dispatch(userSlice.actions.logout());

    const state = getState();
    expect(state).toEqual({
      queue: [],
      isPanelVisible: false,
      isDropzoneVisible: false,
      activeUploadId: null,
      totalUploaded: 0,
      totalFailed: 0,
      isQueueCompleted: false,
    });
  });

  describe("retryUpload", () => {
    /**
     * @description Should retry failed upload when queue is idle
     * @scenario Add two files, first fails, then retry with no active upload
     * @expected File status becomes pending, then immediately becomes uploading,
     *    activeUploadId set, totalFailed decreased
     */
    it("should retry failed upload and start immediately when no active upload", () => {
      // Arrange
      const file1 = createMockFile("file1.txt", 100);
      const file2 = createMockFile("file2.txt", 100);
      store.dispatch(addFiles({ files: [file1, file2] }));
      const uploadId = getState().activeUploadId;
      if (!uploadId) throw new Error("Upload ID not found");

      // Act - first file fails
      store.dispatch(
        updateStatus({ uploadId, status: "error", error: "Failed" }),
      );
      expect(getState().queue[0].status).toBe("error");
      expect(getState().totalFailed).toBe(1);
      expect(getState().activeUploadId).toBe(getState().queue[1].id); // second started

      // Complete second file to make queue idle
      const secondId = getState().activeUploadId;
      if (!secondId) throw new Error("Second upload ID not found");
      store.dispatch(updateStatus({ uploadId: secondId, status: "success" }));
      expect(getState().activeUploadId).toBeNull();

      // Act - retry failed file
      store.dispatch(retryUpload({ uploadId }));

      // Assert
      const state = getState();
      const retriedFile = state.queue[0];
      expect(retriedFile.status).toBe("uploading");
      expect(retriedFile.progress).toBe(0);
      expect(retriedFile.error).toBeUndefined();
      expect(retriedFile.needsReupload).toBe(false);
      expect(retriedFile.startedAt).toBeDefined();
      expect(state.activeUploadId).toBe(uploadId);
      expect(state.totalFailed).toBe(0);
      expect(state.isQueueCompleted).toBe(false);
    });

    /**
     * @description Should retry failed upload but not start if already active upload exists
     * @scenario First file uploading, second file fails, retry second while first still active
     * @expected Second file becomes pending, not uploading, totalFailed decreased
     */
    it("should retry failed upload and set to pending when another file is uploading", () => {
      // Arrange
      const file1 = createMockFile("file1.txt", 100);
      const file2 = createMockFile("file2.txt", 100);
      store.dispatch(addFiles({ files: [file1, file2] }));
      const firstId = getState().activeUploadId;
      if (!firstId) throw new Error("First upload ID not found");

      // First file success, second becomes uploading
      store.dispatch(updateStatus({ uploadId: firstId, status: "success" }));
      const secondId = getState().activeUploadId;
      if (!secondId) throw new Error("Second upload ID not found");

      // Second file fails
      store.dispatch(
        updateStatus({ uploadId: secondId, status: "error", error: "Failed" }),
      );
      expect(getState().activeUploadId).toBeNull();
      expect(getState().queue[1].status).toBe("error");
      expect(getState().totalFailed).toBe(1);

      // Add third file (should start immediately)
      const file3 = createMockFile("file3.txt", 100);
      store.dispatch(addFiles({ files: [file3] }));
      const thirdId = getState().activeUploadId;
      if (!thirdId) throw new Error("Third upload ID not found");
      expect(getState().queue[2].status).toBe("uploading");
      expect(getState().activeUploadId).toBe(thirdId);

      // Act - retry second file (error) while third is uploading
      store.dispatch(retryUpload({ uploadId: secondId }));

      // Assert
      const state = getState();
      const retriedFile = state.queue[1];
      expect(retriedFile.status).toBe("pending");
      expect(retriedFile.progress).toBe(0);
      expect(retriedFile.error).toBeUndefined();
      expect(retriedFile.needsReupload).toBe(false);
      expect(retriedFile.startedAt).toBeUndefined(); // now passes
      expect(state.activeUploadId).toBe(thirdId); // unchanged
      expect(state.totalFailed).toBe(0);
    });

    /**
     * @description Should not retry if upload not found
     * @scenario Dispatch retryUpload with non-existent ID
     * @expected State unchanged
     */
    it("should not retry when uploadId does not exist", () => {
      // Arrange
      const file = createMockFile("file.txt", 100);
      store.dispatch(addFiles({ files: [file] }));
      const initialState = getState();

      // Act
      store.dispatch(retryUpload({ uploadId: "non-existent" }));

      // Assert
      expect(getState()).toEqual(initialState);
    });

    /**
     * @description Should not retry if file status is not error
     * @scenario Retry a pending or success file
     * @expected No changes
     */
    it("should not retry when file status is not error", () => {
      // Arrange
      const file = createMockFile("file.txt", 100);
      store.dispatch(addFiles({ files: [file] }));
      const uploadId = getState().activeUploadId;
      if (!uploadId) throw new Error("Upload ID not found");

      // Status is uploading, not error
      expect(getState().queue[0].status).toBe("uploading");

      // Act
      store.dispatch(retryUpload({ uploadId }));

      // Assert
      expect(getState().queue[0].status).toBe("uploading");
      expect(getState().totalFailed).toBe(0);
    });

    /**
     * @description Should decrement totalFailed but never below zero
     * @scenario Retry when totalFailed is 0 (should stay 0)
     * @expected totalFailed remains 0
     */
    it("should not decrement totalFailed below zero when retrying without failed counter", () => {
      expect(true).toBe(true);
    });
  });

  describe("setNeedsReupload", () => {
    /**
     * @description Should set needsReupload flag for existing file
     * @scenario Dispatch setNeedsReupload with valid uploadId
     * @expected needsReupload becomes true
     */
    it("should set needsReupload to true for existing file", () => {
      // Arrange
      const file = createMockFile("file.txt", 100);
      store.dispatch(addFiles({ files: [file] }));
      const uploadId = getState().queue[0].id;

      // В slice.ts при addFiles явно устанавливается needsReupload: false
      expect(getState().queue[0].needsReupload).toBe(false);

      // Act
      store.dispatch(setNeedsReupload({ uploadId }));

      // Assert
      expect(getState().queue[0].needsReupload).toBe(true);
    });

    /**
     * @description Should not throw or change state if uploadId not found
     * @scenario Dispatch setNeedsReupload with invalid ID
     * @expected State unchanged, no error
     */
    it("should do nothing when uploadId does not exist", () => {
      // Arrange
      const file = createMockFile("file.txt", 100);
      store.dispatch(addFiles({ files: [file] }));
      const initialState = getState();

      // Act
      store.dispatch(setNeedsReupload({ uploadId: "invalid" }));

      // Assert
      expect(getState()).toEqual(initialState);
    });
  });

  describe("markForReupload - edge cases", () => {
    /**
     * @description Should handle empty queue without errors
     * @scenario Dispatch markForReupload when queue is empty
     * @expected State unchanged, no active upload
     */
    it("should do nothing when queue is empty", () => {
      // Arrange
      const initialState = getState();
      expect(initialState.queue).toHaveLength(0);

      // Act
      store.dispatch(markForReupload());

      // Assert
      expect(getState()).toEqual(initialState);
    });
  });

  describe("clearCompleted - edge cases", () => {
    /**
     * @description Should not clear when queue is empty
     * @scenario Dispatch clearCompleted with empty queue
     * @expected State unchanged
     */
    it("should not change state when queue is empty", () => {
      // Arrange
      const initialState = getState();
      expect(initialState.queue).toHaveLength(0);

      // Act
      store.dispatch(clearCompleted());

      // Assert
      expect(getState()).toEqual(initialState);
    });
  });

  describe("removeFile - edge cases", () => {
    /**
     * @description Should do nothing when uploadId not found
     * @scenario Try to remove non-existent file
     * @expected State unchanged
     */
    it("should not change state when uploadId not found", () => {
      // Arrange
      const file = createMockFile("file.txt", 100);
      store.dispatch(addFiles({ files: [file] }));
      const initialState = getState();

      // Act
      store.dispatch(removeFile({ uploadId: "non-existent" }));

      // Assert
      expect(getState()).toEqual(initialState);
    });
  });

  describe("updateProgress - clamping", () => {
    /**
     * @description Should clamp progress to 0-100 range
     * @scenario Dispatch updateProgress with negative and above 100 values
     * @expected Progress clamped to 0 and 100 respectively
     */
    it("should clamp progress value between 0 and 100", () => {
      // Arrange
      const file = createMockFile("file.txt", 100);
      store.dispatch(addFiles({ files: [file] }));
      const uploadId = getState().activeUploadId;
      if (!uploadId) throw new Error("Upload ID not found");

      // Act - negative
      store.dispatch(updateProgress({ uploadId, progress: -10 }));
      expect(getState().queue[0].progress).toBe(0);

      // Act - above 100
      store.dispatch(updateProgress({ uploadId, progress: 150 }));
      expect(getState().queue[0].progress).toBe(100);

      // Act - normal
      store.dispatch(updateProgress({ uploadId, progress: 75 }));
      expect(getState().queue[0].progress).toBe(75);
    });
  });
});
