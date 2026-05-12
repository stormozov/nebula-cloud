import { renderHook } from "@testing-library/react";
import { useNavigate } from "react-router";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import { useAppSelector } from "@/app/store/hooks";

import { useNavigateToUserDisk } from "../useNavigateToUserDisk";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("react-router", () => ({
  useNavigate: vi.fn(),
}));

vi.mock("@/app/store/hooks", () => ({
  useAppSelector: vi.fn(),
}));

// =============================================================================
// TESTS
// =============================================================================

describe("useNavigateToUserDisk", () => {
  const navigateMock = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    (useNavigate as Mock).mockReturnValue(navigateMock);
  });

  describe("when currentUser id matches userId", () => {
    /**
     * @description Should navigate to user's own disk path
     * @scenario currentUser retrieved from store has the same id as the provided userId, navigateToDisk is called
     * @expected navigate is called with "/disk"
     */
    it("should navigate to /disk", () => {
      // Arrange
      (useAppSelector as Mock).mockReturnValue({ id: 123 });
      const userId = 123;
      const { result } = renderHook(() => useNavigateToUserDisk({ userId }));

      // Act
      result.current.navigateToDisk();

      // Assert
      expect(navigateMock).toHaveBeenCalledWith("/disk");
    });
  });

  describe("when currentUser id does not match userId", () => {
    /**
     * @description Should navigate to admin user disk path when user is viewing another user's disk
     * @scenario currentUser has a different id than the provided userId, navigateToDisk is called
     * @expected navigate is called with `/admin/user/${userId}/disk`
     */
    it("should navigate to admin user disk path for different user", () => {
      // Arrange
      (useAppSelector as Mock).mockReturnValue({ id: 999 });
      const userId = 123;
      const { result } = renderHook(() => useNavigateToUserDisk({ userId }));

      // Act
      result.current.navigateToDisk();

      // Assert
      expect(navigateMock).toHaveBeenCalledWith(`/admin/user/${userId}/disk`);
    });
  });

  describe("when currentUser is null or undefined", () => {
    /**
     * @description Should navigate to admin user disk path when current user is not authenticated
     * @scenario useAppSelector returns null or undefined, navigateToDisk is called
     * @expected navigate is called with `/admin/user/${userId}/disk`
     */
    it("should navigate to admin user disk path for unauthenticated user", () => {
      // Arrange
      (useAppSelector as Mock).mockReturnValue(null);
      const userId = 123;
      const { result } = renderHook(() => useNavigateToUserDisk({ userId }));

      // Act
      result.current.navigateToDisk();

      // Assert
      expect(navigateMock).toHaveBeenCalledWith(`/admin/user/${userId}/disk`);
    });

    it("should navigate to admin user disk path when current user is undefined", () => {
      // Arrange
      (useAppSelector as Mock).mockReturnValue(undefined);
      const userId = 456;
      const { result } = renderHook(() => useNavigateToUserDisk({ userId }));

      // Act
      result.current.navigateToDisk();

      // Assert
      expect(navigateMock).toHaveBeenCalledWith(`/admin/user/${userId}/disk`);
    });
  });
});
