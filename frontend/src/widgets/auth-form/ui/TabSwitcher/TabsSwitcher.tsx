import classNames from "classnames";
import type { JSX } from "react";

import type { AuthTab } from "../../lib/tabs.config";
import { AUTH_TABS } from "../../lib/tabs.config";

import "./TabsSwitcher.scss";

/**
 * Tab switcher component for authentication form.
 *
 * Renders clickable tabs for login and registration modes.
 *
 * @param {Object} props - Component props
 * @param {AuthTab} props.activeTab - Currently active tab ID
 * @param {(tab: AuthTab) => void} props.onTabChange - Callback on tab change
 * @param {boolean} props.disabled - Disable tab switching (optional)
 *
 * @returns {JSX.Element} Tab switcher component
 *
 * @example
 * <TabsSwitcher
 *   activeTab="login"
 *   onTabChange={setActiveTab}
 * />
 */
export const TabsSwitcher = ({
  activeTab,
  onTabChange,
  disabled = false,
}: {
  activeTab: AuthTab;
  onTabChange: (tab: AuthTab) => void;
  disabled?: boolean;
}): JSX.Element => {
  const handleTabClick = (tab: AuthTab) => () => {
    if (!disabled) onTabChange(tab);
  };

  return (
    <div
      className="tabs-switcher"
      role="tablist"
      aria-label="Выбор режима авторизации"
    >
      {AUTH_TABS.map((tab) => {
        const isActive = tab.id === activeTab;
        const tabClasses = classNames("tabs-switcher__tab", {
          "tabs-switcher__tab--active": isActive,
          "tabs-switcher__tab--disabled": disabled,
        });

        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={isActive}
            aria-controls={`panel-${tab.id}`}
            id={`tab-${tab.id}`}
            className={tabClasses}
            onClick={handleTabClick(tab.id)}
            disabled={disabled}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  );
};
