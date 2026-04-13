import { useGlobalDragDrop } from "@/features/file/file-upload";
import { PageLayout } from "@/shared/ui";
import { FileManager } from "@/widgets/file-manager";

import "./PageClientDisk.scss";

/**
 * The main client disk page component.
 *
 * This component serves as the entry point for the client's disk interface,
 * enabling drag-and-drop functionality across the page and rendering the file
 * manager within a structured layout.
 */
export default function PageClientDisk() {
  useGlobalDragDrop({ comment: "Загружено через глобальный D&D" });

  return (
    <PageLayout className="page-client-disk">
      <PageLayout.Header />
      <PageLayout.Main className="page-client-disk__main">
        <PageLayout.Container>
          <FileManager />
        </PageLayout.Container>
      </PageLayout.Main>
    </PageLayout>
  );
}
