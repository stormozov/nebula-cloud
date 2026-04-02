import { useParams } from "react-router";

import { LogoutButton } from "@/features/auth";
import { Logo, Navigation, PageLayout } from "@/shared/ui";
import { FileManager } from "@/widgets/file-manager";

import "./PageUserDisk.scss";

/**
 * The page component for displaying a user's file disk interface for admin users.
 */
export default function PageUserDisk() {
  const userId = Number(useParams().userId) || 0;

  return (
    <PageLayout className="page-user-disk">
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
          <FileManager userId={userId} isAdmin />
        </PageLayout.Container>
      </PageLayout.Main>
    </PageLayout>
  );
}
