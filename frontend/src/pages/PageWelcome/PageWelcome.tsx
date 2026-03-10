import { Heading, Logo, PageLayout } from "@/shared/ui";

import "./PageWelcome.scss";

/**
 * Page welcome component.
 */
export default function PageWelcome() {
  return (
    <PageLayout className="page-welcome">
      <PageLayout.Header>
        <PageLayout.Container>
          <Logo />
        </PageLayout.Container>
      </PageLayout.Header>

      <PageLayout.Main>
        <PageLayout.Container>
          <Heading level={1} size="2xl" align="center">
            Добро пожаловать в Nebula Cloud
          </Heading>
        </PageLayout.Container>
      </PageLayout.Main>
    </PageLayout>
  );
}
