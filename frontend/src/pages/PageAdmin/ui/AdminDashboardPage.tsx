import { LogoutButton } from "@/features/auth";
import { Heading, Logo, PageLayout } from "@/shared/ui";
import { UserManagementWidget } from "@/widgets/admin-user-manager";

/**
 * Admin dashboard page component.
 */
export default function AdminDashboardPage() {
  return (
    <PageLayout className="page-admin">
      <PageLayout.Header>
        <PageLayout.Container>
          <PageLayout.Wrapper align="center" justify="space-between">
            <Logo />
            <LogoutButton variant="secondary" />
          </PageLayout.Wrapper>
        </PageLayout.Container>
      </PageLayout.Header>
      <PageLayout.Main className="page-admin__main">
        <PageLayout.Container>
          <Heading level={1} size="xl" align="center">
            Admin Dashboard
          </Heading>
          <UserManagementWidget />
        </PageLayout.Container>
      </PageLayout.Main>
    </PageLayout>
  );
}
