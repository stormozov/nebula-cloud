import { Heading } from "@/shared/ui";
import { AuthForm } from "@/widgets/auth-form";

import "./PageAuth.scss";

/**
 * Authentication page component.
 *
 * This page is accessible only for non-authenticated users (guest role).
 */
export default function PageAuth() {
  const handleAuthSuccess = (): void => {
    // Navigation is handled inside the form hooks
  };

  const handleAuthError = (error: string): void => {
    console.error("Auth error:", error);
  };

  return (
    <div className="page-auth">
      <div className="page-auth__container">
        <div className="page-auth__header">
          <Heading level={1} align="center" className="page-auth__title">
            Nebula Cloud
          </Heading>
          <p className="page-auth__subtitle">
            Ваше надёжное облачное хранилище
          </p>
        </div>

        <AuthForm onSuccess={handleAuthSuccess} onError={handleAuthError} />

        <div className="page-auth__footer">
          <p className="page-auth__disclaimer">
            Входите или регистрируйтесь для доступа к файлам
          </p>
        </div>
      </div>
    </div>
  );
}
