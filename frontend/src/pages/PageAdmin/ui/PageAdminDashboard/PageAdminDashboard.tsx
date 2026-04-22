import { Heading, PageLayout } from "@/shared/ui";
import { UserManagementWidget } from "@/widgets/admin-user-manager";

import "./PageAdminDashboard.scss";

/**
 * The main administration dashboard page component.
 */
export default function PageAdminDashboard() {
  return (
    <PageLayout className="page-admin-dashboard">
      <PageLayout.Header />
      <PageLayout.Main className="page-admin-dashboard__main">
        <PageLayout.Container>
          <PageLayout.Wrapper
            direction="column"
            align="center"
            className="page-admin-dashboard__main-wrapper h-full"
          >
            <Heading level={1} align="center">
              Admin Dashboard
            </Heading>
            <UserManagementWidget />
          </PageLayout.Wrapper>
        </PageLayout.Container>
      </PageLayout.Main>
    </PageLayout>
  );
}
