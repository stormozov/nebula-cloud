import { render, screen } from "@testing-library/react";
import type React from "react";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import { selectIsDropzoneVisible } from "@/entities/file-upload/model/selectors";
import { selectIsAuthenticated } from "@/entities/user/model/selectors";

import { RootLayout } from "../RootLayout";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("react-router", async () => {
  return {
    useNavigate: vi.fn(),
    useLocation: vi.fn(),
    Outlet: () => <div data-testid="outlet" />,
  };
});

vi.mock("@/shared/hooks", () => ({
  useTokenValidation: vi.fn(),
}));

vi.mock("@/features/file/file-upload", () => ({
  useFileUploadProcessor: vi.fn(),
  FileUploadDropzone: vi.fn(({ children }: { children?: React.ReactNode }) => (
    <div data-testid="file-upload-dropzone">{children}</div>
  )),
}));

vi.mock("@/widgets/file-upload-panel", () => ({
  FileUploadPanel: () => <div data-testid="file-upload-panel" />,
}));

vi.mock("react-toastify", () => ({
  ToastContainer: ({ theme }: { theme?: string }) => (
    <div data-testid="toast-container">{theme}</div>
  ),
}));

vi.mock("@/shared/utils", () => ({
  isPublicRoute: vi.fn(),
}));

vi.mock("@/app/store/hooks", () => ({
  useAppSelector: vi.fn(),
}));

import { useLocation, useNavigate } from "react-router";
import { useAppSelector } from "@/app/store/hooks";
import {
  FileUploadDropzone,
  useFileUploadProcessor,
} from "@/features/file/file-upload";
import { useTokenValidation } from "@/shared/hooks";
import { isPublicRoute } from "@/shared/utils";

type SelectorMock = (...args: never[]) => unknown;


const useAppSelectorMock = useAppSelector as unknown as ReturnType<
  typeof vi.fn
>;



const useNavigateMock = useNavigate as unknown as ReturnType<typeof vi.fn>;
const useLocationMock = useLocation as unknown as ReturnType<typeof vi.fn>;

const getSelectorValue = (selector: SelectorMock): unknown => {
  const entry = selectorToValue.get(selector);
  return entry;
};

const selectorToValue = new Map<SelectorMock, unknown>();

const mockUseAppSelector = (selector: SelectorMock, value: unknown) => {
  selectorToValue.set(selector, value);
  useAppSelectorMock.mockImplementation((passedSelector: SelectorMock) =>
    getSelectorValue(passedSelector),
  );
};

// =============================================================================
// TESTS
// =============================================================================

describe("RootLayout", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    selectorToValue.clear();

    (useLocationMock as unknown as Mock).mockReturnValue({
      pathname: "/disk",
    });
    (useNavigateMock as unknown as Mock).mockReturnValue(vi.fn());

    (isPublicRoute as unknown as Mock).mockReturnValue(false);

    mockUseAppSelector(selectIsAuthenticated, false);
    mockUseAppSelector(selectIsDropzoneVisible, false);

    (useTokenValidation as unknown as Mock).mockImplementation(() => {});
    (useFileUploadProcessor as unknown as Mock).mockImplementation(() => {});
  });

  describe("when user tries to access a non-public route", () => {
    /**
     * @description Should redirect to /auth with replace=true when user is not authenticated
     * @scenario RootLayout mounts with isAuthenticated=false and isPublicRoute=false
     * @expected useNavigate is called with "/auth" and { replace: true }
     */
    it("should navigate to /auth with replace=true when user is not authenticated and route is not public", () => {
      // Arrange
      (useLocationMock as unknown as Mock).mockReturnValue({
        pathname: "/private",
      });
      (isPublicRoute as unknown as Mock).mockReturnValue(false);

      mockUseAppSelector(selectIsAuthenticated, false);

      // Act
      renderRootLayout();

      // Assert
      expect(useNavigateMock).toHaveBeenCalledTimes(1);
      const navigateFn = (useNavigateMock as unknown as Mock).mock.results[0]
        .value as ReturnType<typeof vi.fn>;
      expect(navigateFn).toHaveBeenCalledWith("/auth", { replace: true });
    });

    /**
     * @description Should not redirect when user is authenticated even for non-public routes
     * @scenario RootLayout mounts with isAuthenticated=true and isPublicRoute=false
     * @expected useNavigate is not called
     */
    it("should not navigate when user is authenticated", () => {
      // Arrange
      (useLocationMock as unknown as Mock).mockReturnValue({
        pathname: "/private",
      });
      (isPublicRoute as unknown as Mock).mockReturnValue(false);

      mockUseAppSelector(selectIsAuthenticated, true);

      // Act
      renderRootLayout();

      // Assert
      expect(useNavigateMock).toHaveBeenCalledTimes(1);
      const navigateFn = (useNavigateMock as unknown as Mock).mock.results[0]
        .value as ReturnType<typeof vi.fn>;
      expect(navigateFn).not.toHaveBeenCalled();
    });
  });

  describe("when route is public", () => {
    /**
     * @description Should not redirect even if user is not authenticated
     * @scenario RootLayout mounts with isAuthenticated=false and isPublicRoute=true
     * @expected useNavigate is not called
     */
    it("should not navigate when route is public even if user is not authenticated", () => {
      // Arrange
      (useLocationMock as unknown as Mock).mockReturnValue({
        pathname: "/public",
      });
      (isPublicRoute as unknown as Mock).mockReturnValue(true);

      mockUseAppSelector(selectIsAuthenticated, false);

      // Act
      renderRootLayout();

      // Assert
      expect(useNavigateMock).toHaveBeenCalledTimes(1);
      const navigateFn = (useNavigateMock as unknown as Mock).mock.results[0]
        .value as ReturnType<typeof vi.fn>;
      expect(navigateFn).not.toHaveBeenCalled();
    });
  });

  describe("application-level hooks", () => {
    /**
     * @description Should call useTokenValidation on mount
     * @scenario RootLayout mounts
     * @expected useTokenValidation is called
     */
    it("should call useTokenValidation when RootLayout is rendered", () => {
      // Arrange
      // Act
      renderRootLayout();

      // Assert
      expect(useTokenValidation).toHaveBeenCalledTimes(1);
    });

    /**
     * @description Should call useFileUploadProcessor on mount
     * @scenario RootLayout mounts
     * @expected useFileUploadProcessor is called
     */
    it("should call useFileUploadProcessor when RootLayout is rendered", () => {
      // Arrange
      // Act
      renderRootLayout();

      // Assert
      expect(useFileUploadProcessor).toHaveBeenCalledTimes(1);
    });
  });

  describe("global UI components", () => {
    /**
     * @description Should render ToastContainer and FileUploadPanel on mount
     * @scenario RootLayout mounts
     * @expected ToastContainer theme and FileUploadPanel are present
     */
    it("should render ToastContainer and FileUploadPanel when RootLayout is rendered", () => {
      // Arrange

      // Act
      renderRootLayout();

      // Assert
      expect(screen.getByTestId("toast-container")).toHaveTextContent(
        "colored",
      );
      expect(screen.getByTestId("file-upload-panel")).toBeInTheDocument();
    });

    /**
     * @description Should render global FileUploadDropzone when it is enabled in the store
     * @scenario isDropzoneVisible=true
     * @expected FileUploadDropzone is rendered with correct props
     */
    it("should render global FileUploadDropzone when dropzone is visible with clickable=false and disabled=false", () => {
      // Arrange
      mockUseAppSelector(selectIsDropzoneVisible, true);

      // Act
      renderRootLayout();

      // Assert
      expect(screen.getByTestId("file-upload-dropzone")).toBeInTheDocument();

      expect(FileUploadDropzone).toHaveBeenCalled();
      const [[propsArg]] = (FileUploadDropzone as unknown as Mock).mock.calls;

      expect(propsArg).toEqual(
        expect.objectContaining({
          mode: "global",
          clickable: false,
          disabled: false,
        }),
      );
    });

    /**
     * @description Should not render global FileUploadDropzone when it is disabled in the store
     * @scenario isDropzoneVisible=false
     * @expected FileUploadDropzone is not rendered
     */
    it("should not render FileUploadDropzone when dropzone is not visible", () => {
      // Arrange
      mockUseAppSelector(selectIsDropzoneVisible, false);

      // Act
      renderRootLayout();

      // Assert
      expect(screen.queryByTestId("file-upload-dropzone")).toBeNull();
    });
  });
});

const renderRootLayout = () => {
  return render(<RootLayout />);
};
