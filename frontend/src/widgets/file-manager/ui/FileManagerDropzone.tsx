import { FileUploadDropzone } from "@/features/file/file-upload";

/**
 * Props for the FileManagerDropzone component.
 */
interface FileManagerDropzoneProps {
  /** Controls the visibility of the dropzone. */
  isVisible: boolean;
}

/**
 * A conditional wrapper component that displays a file upload dropzone
 * only when specified by the isVisible prop.
 *
 * When visible, renders a FileUploadDropzone configured for local uploads
 * with multiple file selection enabled and a default comment.
 * The dropzone overlays the file manager to allow drag-and-drop uploads.
 */
export function FileManagerDropzone({ isVisible }: FileManagerDropzoneProps) {
  if (!isVisible) return null;

  return (
    <div className="file-manager__dropzone">
      <FileUploadDropzone
        mode="local"
        clickable={true}
        multiple={true}
        comment="Загружено через FileManager"
      />
    </div>
  );
}
