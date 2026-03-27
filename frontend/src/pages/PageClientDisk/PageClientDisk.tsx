import { LogoutButton } from "@/features/auth";
import { useGlobalDragDrop } from "@/features/file/file-upload";
import { Logo, Navigation, PageLayout } from "@/shared/ui";

import "./PageClientDisk.scss";
import { FileManager } from "@/widgets/file-manager";

/**
 * Page client disk component.
 */
export default function PageClientDisk() {
  useGlobalDragDrop({ comment: "Загружено через глобальный D&D" });

  return (
    <PageLayout className="page-client-disk">
      <PageLayout.Header>
        <PageLayout.Container>
          <PageLayout.Wrapper align="center" justify="space-between">
            <Logo />
            <Navigation />
            <LogoutButton variant="secondary" />
          </PageLayout.Wrapper>
        </PageLayout.Container>
      </PageLayout.Header>

      <PageLayout.Main className="page-client-disk__main">
        <PageLayout.Container>
          <FileManager />
        </PageLayout.Container>
      </PageLayout.Main>
    </PageLayout>
  );
}
