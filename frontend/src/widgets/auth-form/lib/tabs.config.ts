/**
 * Auth tab types.
 */
export type AuthTab = "login" | "register";

/**
 * Tab configuration interface.
 */
export interface ITabConfig {
  id: AuthTab;
  label: string;
}

/**
 * Configuration for authentication form tabs.
 *
 * Defines available tabs with their IDs and display labels.
 */
export const AUTH_TABS: ITabConfig[] = [
  { id: "login", label: "Вход" },
  { id: "register", label: "Регистрация" },
];

/**
 * Default active tab on form mount.
 */
export const DEFAULT_AUTH_TAB: AuthTab = "login";

/**
 * Props for TabSwitcher component
 */
export interface ITabSwitcherProps {
  activeTab: AuthTab;
  onTabChange: (tab: AuthTab) => void;
  disabled?: boolean;
}

/**
 * Props for AuthForm component.
 */
export interface IAuthFormProps {
  onSuccess?: () => void;
  onError?: (error: string) => void;
}
