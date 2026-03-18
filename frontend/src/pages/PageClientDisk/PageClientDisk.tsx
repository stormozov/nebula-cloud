import "./PageClientDisk.scss";

import {
  FileUploadDropzone,
  useGlobalDragDrop,
} from "@/features/file/file-upload";

/**
 * Page client disk component.
 */
export default function PageClientDisk() {
  useGlobalDragDrop({
    comment: "Загружено через глобальный D&D",
  });

  return (
    <div className="page-client-disk">
      <h1>PageClientDisk</h1>
      <FileUploadDropzone />
    </div>
  );
}
