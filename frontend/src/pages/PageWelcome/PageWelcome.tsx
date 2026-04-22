import { RegisterButton } from "@/features/auth";
import {
  AdvantagesList,
  AppFeatures,
  Heading,
  Logo,
  PageLayout,
} from "@/shared/ui";
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
          <PageLayout.Wrapper
            align="center"
            justify="space-between"
            className="page__header-wrapper"
          >
            <Logo />
            <AuthActions />
          </PageLayout.Wrapper>
        </PageLayout.Container>
      </PageLayout.Header>

      <PageLayout.Main className="page-welcome__main">
        <PageLayout.Container className="page-welcome__container">
          <section className="page-welcome__welcome-section">
            <Heading level={1} align="center">
              Добро пожаловать в Nebula Cloud
            </Heading>
            <p className="page-welcome__subtitle">
              Безопасное облачное хранилище для ваших файлов. Загружайте,
              храните и делитесь документами с простым и удобным интерфейсом.
            </p>
            <AuthActions registerFirst />
          </section>

          <section className="page-welcome__advantages-section">
            <AdvantagesList />
          </section>

          <section className="page-welcome__features-section">
            <AppFeatures
              titleProps={{
                children: "Возможности приложения",
                className: "page-welcome__features-title",
                align: "center",
                noMargin: true,
              }}
            />
          </section>

          <section className="page-welcome__register-section">
            <Heading level={2}>Готовы начать работу?</Heading>
            <p className="page-welcome__subtitle">
              Создайте аккаунт и получите доступ к своему облачному хранилищу
            </p>
            <RegisterButton>Зарегистрироваться бесплатно</RegisterButton>
          </section>
        </PageLayout.Container>
      </PageLayout.Main>
    </PageLayout>
  );
}
