import { useNavigate } from "react-router";

import { Button, Heading, Icon, PageLayout } from "@/shared/ui";

import "./PageNotFound.scss";

/**
 * Component representing the "Page Not Found" page.
 */
export default function PageNotFound() {
  const navigate = useNavigate();

  return (
    <PageLayout className="page-not-found">
      <PageLayout.Header />
      <PageLayout.Main className="page-not-found__main">
        <PageLayout.Container>
          <div className="page-not-found__content-card">
            <div className="page-not-found__icon-wrapper">
              <Icon
                name="cloudBad"
                size={256}
                color="var(--color-text-tertiary)"
                className="page-not-found__icon"
              />
              <Icon
                name="notFound"
                size={128}
                color="var(--color-warning)"
                className="page-not-found__icon-404"
              />
            </div>

            <Heading level={1} size="2xl" align="center">
              Облако не всегда пушистое: здесь — 404
            </Heading>

            <p className="page-not-found__subtitle">
              Эта страница затерялась где-то среди облаков. Возможно, её унёс
              цифровой ветер или она просто решила спрятаться
            </p>

            <Button
              variant="primary"
              size="large"
              icon={{ name: "cloud" }}
              onClick={() => navigate("/")}
            >
              На главную
            </Button>
          </div>
        </PageLayout.Container>
      </PageLayout.Main>
    </PageLayout>
  );
}
