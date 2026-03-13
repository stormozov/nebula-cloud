import { Heading, Logo, PageLayout } from "@/shared/ui";
import { AuthActions } from "@/widgets/auth-actions";

import "./PageWelcome.scss";

/**
 * Component representing the Welcome page.
 */
export default function PageWelcome() {
  return (
    <PageLayout className="page-welcome">
      <PageLayout.Header>
        <PageLayout.Container>
          <PageLayout.Wrapper className="page__header-wrapper">
            <Logo />
            <AuthActions />
          </PageLayout.Wrapper>
        </PageLayout.Container>
      </PageLayout.Header>

      <PageLayout.Main className="page-welcome__main">
        <PageLayout.Container>
          <Heading level={1} size="2xl" align="center">
            Добро пожаловать в Nebula Cloud
          </Heading>
        </PageLayout.Container>
      </PageLayout.Main>
    </PageLayout>
  );
}
