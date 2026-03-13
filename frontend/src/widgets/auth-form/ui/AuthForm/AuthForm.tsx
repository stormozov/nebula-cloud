import { useCallback, useState } from "react";
import { useSearchParams } from "react-router";

import { LoginForm } from "@/features/auth/login-by-email";
import { RegisterForm } from "@/features/auth/register-by-email";

import type { AuthTab, IAuthFormProps } from "../../lib/tabs.config";
import { DEFAULT_AUTH_TAB } from "../../lib/tabs.config";
import { TabsSwitcher } from "../TabSwitcher/TabsSwitcher";

import "./AuthForm.scss";

/**
 * Main authentication form widget.
 *
 * Combines login and registration forms with tab switching.
 * Manages active tab state and renders appropriate form.
 *
 * @param {Object} props - Component props
 * @param {() => void} props.onSuccess - Callback on successful auth (optional)
 * @param {(error: string) => void} props.onError - Callback on auth error
 *  (optional)
 *
 * @example
 * <AuthForm
 *   onSuccess={() => navigate('/disk')}
 *   onError={(msg) => setGlobalError(msg)}
 * />
 */
export const AuthForm = ({ onSuccess, onError }: IAuthFormProps) => {
  const [searchParams, setSearchParams] = useSearchParams();

  const [activeTab, setActiveTab] = useState<AuthTab>(() => {
    const tabParam = searchParams.get("tab") as AuthTab | null;
    return tabParam === "register" ? "register" : DEFAULT_AUTH_TAB;
  });

  /**
   * Handle tab change.
   */
  const handleTabChange = useCallback(
    (tab: AuthTab): void => {
      setActiveTab(tab);
      setSearchParams(tab === "register" ? { tab: "register" } : {});
    },
    [setSearchParams],
  );

  return (
    <section className="auth-form" aria-label="Форма авторизации">
      <TabsSwitcher activeTab={activeTab} onTabChange={handleTabChange} />

      <div
        className="auth-form__panel"
        id={`panel-${activeTab}`}
        role="tabpanel"
        aria-labelledby={`tab-${activeTab}`}
      >
        {activeTab === "login" ? (
          <LoginForm onSuccess={onSuccess} onError={onError} />
        ) : (
          <RegisterForm onSuccess={onSuccess} onError={onError} />
        )}
      </div>
    </section>
  );
};
