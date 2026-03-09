import { Logo, PageLayout } from "@/shared/ui";

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
          <h1>Добро пожаловать в Nebula Cloud</h1>
        </PageLayout.Container>
      </PageLayout.Main>
    </PageLayout>
  );
}
