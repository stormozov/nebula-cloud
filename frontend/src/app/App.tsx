import { Provider } from "react-redux";
import { RouterProvider } from "react-router";

import { selectIsDropzoneVisible } from "@/entities/file-upload";
import {
  FileUploadDropzone,
  useFileUploadProcessor,
} from "@/features/file/file-upload";
import { FileUploadPanel } from "@/widgets/file-upload-panel";

import { routesConfig } from "./routes";
import { useAppSelector } from "./store/hooks";
import { store } from "./store/store";

function AppContent() {
  const isDropzoneVisible = useAppSelector(selectIsDropzoneVisible);

  useFileUploadProcessor();

  return (
    <>
      <RouterProvider router={routesConfig} />

      {/* Global overlay dropzone */}
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
