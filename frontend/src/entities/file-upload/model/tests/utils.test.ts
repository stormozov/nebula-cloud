import { describe, expect, it, vi } from "vitest";
import type { IUploadFile } from "../types";
import {
  areAllUploadsCompleted,
  findNextPendingFile,
  generateUploadId,
} from "../utils";

describe("utils", () => {
  describe("generateUploadId", () => {
    /**
     * @description Should return a string starting with "upload_" and containing timestamp + random characters
     * @scenario Call generateUploadId without any parameters
     * @expected Returns string in format "upload_{timestamp}_{7 random alphanumeric chars}"
     */
    it("should return upload ID with correct format", () => {
      // Arrange
      const mockTimestamp = 1678901234567;
      const mockRandom = 0.123456;
      vi.spyOn(Date, "now").mockReturnValue(mockTimestamp);
      vi.spyOn(Math, "random").mockReturnValue(mockRandom);

      const expectedRandomPart = mockRandom.toString(36).substring(2, 9);

      // Act
      const result = generateUploadId();

      // Assert
      expect(result).toBe(`upload_${mockTimestamp}_${expectedRandomPart}`);
    });

    /**
     * @description Should generate different IDs on consecutive calls
     * @scenario Call generateUploadId twice in a row
     * @expected Two different strings
     */
    it("should generate unique IDs on multiple calls", () => {
      // Arrange
      const timestamp1 = 1000;
      const timestamp2 = 2000;
      vi.spyOn(Date, "now")
        .mockReturnValueOnce(timestamp1)
        .mockReturnValueOnce(timestamp2);
      vi.spyOn(Math, "random")
        .mockReturnValueOnce(0.1)
        .mockReturnValueOnce(0.2);

      // Act
      const id1 = generateUploadId();
      const id2 = generateUploadId();

      // Assert
      expect(id1).toBe(
        `upload_${timestamp1}_${(0.1).toString(36).substring(2, 9)}`,
      );
      expect(id2).toBe(
        `upload_${timestamp2}_${(0.2).toString(36).substring(2, 9)}`,
      );
      expect(id1).not.toBe(id2);
    });
  });

  describe("findNextPendingFile", () => {
    const createMockFile = (status: IUploadFile["status"]): IUploadFile => ({
      id: "1",
      file: {
        name: "test.jpg",
        size: 1024,
        type: "image/jpeg",
        lastModified: Date.now(),
      },
      status,
      progress: 0,
    });

    /**
     * @description Should return the first file with status "pending"
     * @scenario Queue contains files with statuses "success", "pending", "error"
     * @expected Returns the pending file object
     */
    it("should return first pending file when queue has pending status", () => {
      // Arrange
      const queue: IUploadFile[] = [
        createMockFile("success"),
        createMockFile("pending"),
        createMockFile("error"),
      ];

      // Act
      const result = findNextPendingFile(queue);

      // Assert
      expect(result).toBe(queue[1]);
      expect(result?.status).toBe("pending");
    });

    /**
     * @description Should return undefined when no file has status "pending"
     * @scenario Queue contains only "success" and "error" files
     * @expected Returns undefined
     */
    it("should return undefined when no pending file exists", () => {
      // Arrange
      const queue: IUploadFile[] = [
        createMockFile("success"),
        createMockFile("error"),
        createMockFile("success"),
      ];

      // Act
      const result = findNextPendingFile(queue);

      // Assert
      expect(result).toBeUndefined();
    });

    /**
     * @description Should return undefined for empty queue
     * @scenario Queue is an empty array
     * @expected Returns undefined
     */
    it("should return undefined when queue is empty", () => {
      // Arrange
      const queue: IUploadFile[] = [];

      // Act
      const result = findNextPendingFile(queue);

      // Assert
      expect(result).toBeUndefined();
    });
  });

  describe("areAllUploadsCompleted", () => {
    const createMockFile = (status: IUploadFile["status"]): IUploadFile => ({
      id: "1",
      file: {
        name: "test.jpg",
        size: 1024,
        type: "image/jpeg",
        lastModified: Date.now(),
      },
      status,
      progress: 0,
    });

    /**
     * @description Should return true when all files have status "success" or "error"
     * @scenario Queue contains only "success" and "error" files
     * @expected Returns true
     */
    it("should return true when all files are success or error", () => {
      // Arrange
      const queue: IUploadFile[] = [
        createMockFile("success"),
        createMockFile("error"),
        createMockFile("success"),
      ];

      // Act
      const result = areAllUploadsCompleted(queue);

      // Assert
      expect(result).toBe(true);
    });

    /**
     * @description Should return false when at least one file has status "pending"
     * @scenario Queue contains a pending file among success/error files
     * @expected Returns false
     */
    it("should return false when any file has pending status", () => {
      // Arrange
      const queue: IUploadFile[] = [
        createMockFile("success"),
        createMockFile("pending"),
        createMockFile("error"),
      ];

      // Act
      const result = areAllUploadsCompleted(queue);

      // Assert
      expect(result).toBe(false);
    });

    /**
     * @description Should return false for empty queue (length > 0 condition)
     * @scenario Queue is an empty array
     * @expected Returns false
     */
    it("should return false when queue is empty", () => {
      // Arrange
      const queue: IUploadFile[] = [];

      // Act
      const result = areAllUploadsCompleted(queue);

      // Assert
      expect(result).toBe(false);
    });

    /**
     * @description Should return true when a single file is success or error
     * @scenario Queue has exactly one file with status "success" or "error"
     * @expected Returns true
     */
    it("should return true when single file is success", () => {
      // Arrange
      const queue: IUploadFile[] = [createMockFile("success")];

      // Act
      const result = areAllUploadsCompleted(queue);

      // Assert
      expect(result).toBe(true);
    });

    it("should return true when single file is error", () => {
      // Arrange
      const queue: IUploadFile[] = [createMockFile("error")];

      // Act
      const result = areAllUploadsCompleted(queue);

      // Assert
      expect(result).toBe(true);
    });
  });
});
