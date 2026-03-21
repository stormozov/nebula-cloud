import { useEffect } from "react";
import { Outlet, useLocation, useNavigate } from "react-router";

import { useAppSelector } from "@/app/store/hooks";
import { selectIsDropzoneVisible } from "@/entities/file-upload";
import { selectIsAuthenticated } from "@/entities/user";
import {
  FileUploadDropzone,
  useFileUploadProcessor,
} from "@/features/file/file-upload";
import { useTokenValidation } from "@/shared/hooks";
import { isPublicRoute } from "@/shared/utils";
import { FileUploadPanel } from "@/widgets/file-upload-panel";

/**
 * The root layout component of the application.
 *
 * @remarks
 * - Redirects unauthenticated users to the `/auth` page if they attempt
 *    to access a non-public route.
 * - Runs periodic token validation via {@link useTokenValidation}.
 * - Processes queued file uploads using {@link useFileUploadProcessor}.
 * - Conditionally renders the global file upload dropzone based
 *    on application state.
 * ```
 */
export const RootLayout = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const isAuthenticated = useAppSelector(selectIsAuthenticated);

  useEffect(() => {
    if (!isAuthenticated && !isPublicRoute(location.pathname)) {
      navigate("/auth", { replace: true });
    }
  }, [isAuthenticated, location.pathname, navigate]);

  useTokenValidation();
  useFileUploadProcessor();

  const isDropzoneVisible = useAppSelector(selectIsDropzoneVisible);

  return (
    <>
      <Outlet />

      {isDropzoneVisible && (
        <FileUploadDropzone mode="global" clickable={false} disabled={false} />
      )}

      <FileUploadPanel />
    </>
  );
};
