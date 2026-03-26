import { LogoutButton } from "@/features/auth";
import { Heading, Logo, PageLayout } from "@/shared/ui";
import { UserManagementWidget } from "@/widgets/admin-user-manager";

import "./AdminDashboardPage.scss";

/**
 * Admin dashboard page component.
 */
export default function AdminDashboardPage() {
  return (
    <PageLayout className="page-admin-dashboard">
      <PageLayout.Header>
        <PageLayout.Container>
          <PageLayout.Wrapper align="center" justify="space-between">
            <Logo />
            <LogoutButton variant="secondary" />
          </PageLayout.Wrapper>
        </PageLayout.Container>
      </PageLayout.Header>
      <PageLayout.Main className="page-admin-dashboard__main">
        <PageLayout.Container className="h-full">
          <PageLayout.Wrapper
            direction="column"
            align="center"
            className="page-admin-dashboard__main-wrapper h-full"
          >
            <Heading level={1} size="xl" align="center">
              Admin Dashboard
            </Heading>
            <UserManagementWidget />
          </PageLayout.Wrapper>
        </PageLayout.Container>
      </PageLayout.Main>
    </PageLayout>
  );
}
