import { useEffect } from "react";
import { Provider } from "react-redux";
import { RouterProvider } from "react-router";

import { selectIsDropzoneVisible } from "@/entities/file-upload";
import { logout } from "@/entities/user/model/slice";
import {
  FileUploadDropzone,
  useFileUploadProcessor,
} from "@/features/file/file-upload";
import { isTokenExpired } from "@/shared/utils";
import { getAccessTokenFromPersist } from "@/shared/utils/getPersistedAuthState";
import { FileUploadPanel } from "@/widgets/file-upload-panel";

import { routesConfig } from "./routes";
import { useAppSelector } from "./store/hooks";
import { store } from "./store/store";

function AppContent() {
  useEffect(() => {
    const validateToken = () => {
      const token = getAccessTokenFromPersist();
      if (token && isTokenExpired(token)) {
        localStorage.removeItem("persist:auth");
        store.dispatch(logout());
      }
    };

    validateToken(); // initial

    const interval = setInterval(validateToken, 5 * 60 * 1000); // 5min
    window.addEventListener("focus", validateToken);

    return () => {
      clearInterval(interval);
      window.removeEventListener("focus", validateToken);
    };
  }, []);

  const isDropzoneVisible = useAppSelector(selectIsDropzoneVisible);

  useFileUploadProcessor();

  return (
    <>
      <RouterProvider router={routesConfig} />
      {isDropzoneVisible && (
        <FileUploadDropzone mode="global" clickable={false} disabled={false} />
      )}
    </>
  );
}

function App() {
  return (
    <Provider store={store}>
      <AppContent />
      <FileUploadPanel />
    </Provider>
  );
}

export default App;
