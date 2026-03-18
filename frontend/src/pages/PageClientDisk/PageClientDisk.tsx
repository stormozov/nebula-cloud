import { LogoutButton } from "@/features/auth";
import { useGlobalDragDrop } from "@/features/file/file-upload";
import { Logo, PageLayout } from "@/shared/ui";

import "./PageClientDisk.scss";

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
            <LogoutButton variant="secondary" />
          </PageLayout.Wrapper>
        </PageLayout.Container>
      </PageLayout.Header>
    </PageLayout>
  );
}
