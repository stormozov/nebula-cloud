import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { TabsSwitcher } from "./TabsSwitcher";

// =============================================================================
// MOCKS CONFIGURATION
// =============================================================================

// Mock for 'classnames' utility with proper object syntax support
vi.mock("classnames", () => ({
  default: vi.fn(
    (...classes: (string | undefined | Record<string, boolean>)[]) => {
      const processedClasses: string[] = [];

      for (const cls of classes) {
        if (typeof cls === "string" && cls) {
          processedClasses.push(cls);
        } else if (typeof cls === "object" && cls !== null) {
          for (const [key, value] of Object.entries(cls)) {
            if (value === true && typeof key === "string" && key) {
              processedClasses.push(key);
            }
          }
        }
      }

      return processedClasses.join(" ");
    },
  ),
}));

// Mock for tabs config - defined INSIDE the factory to avoid hoisting issues
vi.mock("../../lib/tabs.config", () => {
  const MOCK_AUTH_TABS: Array<{ id: "login" | "register"; label: string }> = [
    { id: "login", label: "Вход" },
    { id: "register", label: "Регистрация" },
  ];
  return {
    AUTH_TABS: MOCK_AUTH_TABS,
  };
});

// =============================================================================
// TEST HELPERS
// =============================================================================

const TABS_BTN_LABELS = {
  login: "Вход",
  register: "Регистрация",
};

/**
 * Helper to get tab button by label
 * @param label - The tab label text
 * @returns The tab button element
 */
const getTabButton = (label: string) =>
  screen.getByRole("tab", { name: label });

// =============================================================================
// TEST SUITE
// =============================================================================

describe("TabsSwitcher", () => {
  const mockOnTabChange = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    mockOnTabChange.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ---------------------------------------------------------------------------
  // Rendering Tests
  // ---------------------------------------------------------------------------

  describe("Rendering", () => {
    /**
     * @description Should render all tabs from AUTH_TABS config
     * @scenario Component rendered with default props should display all configured tabs
     * @expected Two tab buttons rendered with labels "Вход" and "Регистрация"
     */
    it("should render all tabs from AUTH_TABS config", () => {
      render(<TabsSwitcher activeTab="login" onTabChange={mockOnTabChange} />);

      const loginTab = getTabButton(TABS_BTN_LABELS.login);
      const registerTab = getTabButton(TABS_BTN_LABELS.register);

      expect(loginTab).toBeInTheDocument();
      expect(registerTab).toBeInTheDocument();
    });

    /**
     * @description Should apply active class to current tab
     * @scenario activeTab="login" should add "tabs-switcher__tab--active" to login tab
     * @expected Login tab className contains "tabs-switcher__tab--active", register does not
     */
    it("should apply active class to current tab", () => {
      render(<TabsSwitcher activeTab="login" onTabChange={mockOnTabChange} />);

      const loginTab = getTabButton(TABS_BTN_LABELS.login);
      const registerTab = getTabButton(TABS_BTN_LABELS.register);

      expect(loginTab.className).toContain("tabs-switcher__tab--active");
      expect(registerTab.className).not.toContain("tabs-switcher__tab--active");
    });

    /**
     * @description Should apply base class to all tabs
     * @scenario All tab buttons should have "tabs-switcher__tab" base class
     * @expected Both tabs have className containing "tabs-switcher__tab"
     */
    it("should apply base class to all tabs", () => {
      render(<TabsSwitcher activeTab="login" onTabChange={mockOnTabChange} />);

      const loginTab = getTabButton(TABS_BTN_LABELS.login);
      const registerTab = getTabButton(TABS_BTN_LABELS.register);

      expect(loginTab.className).toContain("tabs-switcher__tab");
      expect(registerTab.className).toContain("tabs-switcher__tab");
    });

    /**
     * @description Should render tabs with correct ARIA attributes
     * @scenario Each tab should have role, aria-selected, aria-controls, and id
     * @expected Tab buttons have correct accessibility attributes
     */
    it("should render tabs with correct ARIA attributes", () => {
      render(
        <TabsSwitcher activeTab="register" onTabChange={mockOnTabChange} />,
      );

      const loginTab = getTabButton(TABS_BTN_LABELS.login);
      const registerTab = getTabButton(TABS_BTN_LABELS.register);

      expect(loginTab).toHaveAttribute("role", "tab");
      expect(loginTab).toHaveAttribute("aria-selected", "false");
      expect(loginTab).toHaveAttribute("aria-controls", "panel-login");
      expect(loginTab).toHaveAttribute("id", "tab-login");

      expect(registerTab).toHaveAttribute("role", "tab");
      expect(registerTab).toHaveAttribute("aria-selected", "true");
      expect(registerTab).toHaveAttribute("aria-controls", "panel-register");
      expect(registerTab).toHaveAttribute("id", "tab-register");
    });

    /**
     * @description Should render tabs with button type
     * @scenario Tab buttons should have type="button" to prevent form submission
     * @expected All tab buttons have type="button" attribute
     */
    it("should render tabs with button type", () => {
      render(<TabsSwitcher activeTab="login" onTabChange={mockOnTabChange} />);

      const loginTab = getTabButton(TABS_BTN_LABELS.login);
      const registerTab = getTabButton(TABS_BTN_LABELS.register);

      expect(loginTab).toHaveAttribute("type", "button");
      expect(registerTab).toHaveAttribute("type", "button");
    });
  });

  // ---------------------------------------------------------------------------
  // Interaction Tests - Enabled State
  // ---------------------------------------------------------------------------

  describe("Interaction - Enabled", () => {
    /**
     * @description Should call onTabChange when inactive tab is clicked
     * @scenario User clicks on "Регистрация" tab when "login" is active
     * @expected onTabChange called with "register" exactly once
     */
    it("should call onTabChange when inactive tab is clicked", () => {
      render(<TabsSwitcher activeTab="login" onTabChange={mockOnTabChange} />);

      const registerTab = getTabButton(TABS_BTN_LABELS.register);
      fireEvent.click(registerTab);

      expect(mockOnTabChange).toHaveBeenCalledTimes(1);
      expect(mockOnTabChange).toHaveBeenCalledWith("register");
    });

    /**
     * @description Should call onTabChange when active tab is clicked
     * @scenario User clicks on already active "login" tab
     * @expected onTabChange called with "login" (component doesn't prevent re-selection)
     */
    it("should call onTabChange when active tab is clicked", () => {
      render(<TabsSwitcher activeTab="login" onTabChange={mockOnTabChange} />);

      const loginTab = getTabButton(TABS_BTN_LABELS.login);
      fireEvent.click(loginTab);

      expect(mockOnTabChange).toHaveBeenCalledTimes(1);
      expect(mockOnTabChange).toHaveBeenCalledWith("login");
    });

    /**
     * @description Should handle multiple tab switches correctly
     * @scenario User clicks multiple tabs in sequence
     * @expected onTabChange called with correct tab id on each click
     */
    it("should handle multiple tab switches correctly", () => {
      render(<TabsSwitcher activeTab="login" onTabChange={mockOnTabChange} />);

      const loginTab = getTabButton(TABS_BTN_LABELS.login);
      const registerTab = getTabButton(TABS_BTN_LABELS.register);

      fireEvent.click(registerTab);
      expect(mockOnTabChange).toHaveBeenCalledWith("register");

      fireEvent.click(loginTab);
      expect(mockOnTabChange).toHaveBeenCalledWith("login");

      expect(mockOnTabChange).toHaveBeenCalledTimes(2);
    });
  });

  // ---------------------------------------------------------------------------
  // Interaction Tests - Disabled State
  // ---------------------------------------------------------------------------

  describe("Interaction - Disabled", () => {
    /**
     * @description Should apply disabled class to all tabs when disabled prop is true
     * @scenario disabled={true} should add "tabs-switcher__tab--disabled" class
     * @expected All tab buttons have className containing "tabs-switcher__tab--disabled"
     */
    it("should apply disabled class to all tabs when disabled prop is true", () => {
      render(
        <TabsSwitcher
          activeTab="login"
          onTabChange={mockOnTabChange}
          disabled={true}
        />,
      );

      const loginTab = getTabButton(TABS_BTN_LABELS.login);
      const registerTab = getTabButton(TABS_BTN_LABELS.register);

      expect(loginTab.className).toContain("tabs-switcher__tab--disabled");
      expect(registerTab.className).toContain("tabs-switcher__tab--disabled");
    });

    /**
     * @description Should not call onTabChange when disabled and tab is clicked
     * @scenario disabled={true} and user clicks on a tab
     * @expected onTabChange not called, button has disabled attribute
     */
    it("should not call onTabChange when disabled and tab is clicked", () => {
      render(
        <TabsSwitcher
          activeTab="login"
          onTabChange={mockOnTabChange}
          disabled={true}
        />,
      );

      const registerTab = getTabButton(TABS_BTN_LABELS.register);

      expect(registerTab).toBeDisabled();
      fireEvent.click(registerTab);

      expect(mockOnTabChange).not.toHaveBeenCalled();
    });

    /**
     * @description Should not apply disabled class when disabled is false
     * @scenario disabled={false} or undefined should not add disabled modifier
     * @expected Tab buttons do not have "tabs-switcher__tab--disabled" class
     */
    it("should not apply disabled class when disabled is false", () => {
      render(
        <TabsSwitcher
          activeTab="login"
          onTabChange={mockOnTabChange}
          disabled={false}
        />,
      );

      const loginTab = getTabButton(TABS_BTN_LABELS.login);
      const registerTab = getTabButton(TABS_BTN_LABELS.register);

      expect(loginTab.className).not.toContain("tabs-switcher__tab--disabled");
      expect(registerTab.className).not.toContain(
        "tabs-switcher__tab--disabled",
      );
    });

    /**
     * @description Should have disabled attribute on buttons when disabled prop is true
     * @scenario disabled={true} should set disabled attribute on all tab buttons
     * @expected All tab buttons have disabled attribute
     */
    it("should have disabled attribute on buttons when disabled prop is true", () => {
      render(
        <TabsSwitcher
          activeTab="login"
          onTabChange={mockOnTabChange}
          disabled={true}
        />,
      );

      const loginTab = getTabButton(TABS_BTN_LABELS.login);
      const registerTab = getTabButton(TABS_BTN_LABELS.register);

      expect(loginTab).toBeDisabled();
      expect(registerTab).toBeDisabled();
    });
  });

  // ---------------------------------------------------------------------------
  // Integration Tests
  // ---------------------------------------------------------------------------

  describe("Integration", () => {
    /**
     * @description Should update aria-selected when activeTab changes
     * @scenario Re-render with different activeTab should update ARIA state
     * @expected aria-selected reflects the new active tab
     */
    it("should update aria-selected when activeTab changes", () => {
      const { rerender } = render(
        <TabsSwitcher activeTab="login" onTabChange={mockOnTabChange} />,
      );

      let loginTab = getTabButton(TABS_BTN_LABELS.login);
      let registerTab = getTabButton(TABS_BTN_LABELS.register);

      expect(loginTab).toHaveAttribute("aria-selected", "true");
      expect(registerTab).toHaveAttribute("aria-selected", "false");

      rerender(
        <TabsSwitcher activeTab="register" onTabChange={mockOnTabChange} />,
      );

      loginTab = getTabButton(TABS_BTN_LABELS.login);
      registerTab = getTabButton(TABS_BTN_LABELS.register);

      expect(loginTab).toHaveAttribute("aria-selected", "false");
      expect(registerTab).toHaveAttribute("aria-selected", "true");
    });

    /**
     * @description Should handle tab click with disabled state toggle
     * @scenario Component disabled state changes from false to true
     * @expected Tabs become disabled and unclickable after prop change
     */
    it("should handle tab click with disabled state toggle", () => {
      const { rerender } = render(
        <TabsSwitcher
          activeTab="login"
          onTabChange={mockOnTabChange}
          disabled={false}
        />,
      );

      const registerTab = getTabButton(TABS_BTN_LABELS.register);
      fireEvent.click(registerTab);
      expect(mockOnTabChange).toHaveBeenCalledWith("register");

      mockOnTabChange.mockClear();
      rerender(
        <TabsSwitcher
          activeTab="register"
          onTabChange={mockOnTabChange}
          disabled={true}
        />,
      );

      const loginTab = getTabButton("Вход");
      fireEvent.click(loginTab);
      expect(mockOnTabChange).not.toHaveBeenCalled();
    });

    /**
     * @description Should render with correct container structure
     * @scenario Component should render tabs inside a div with base class
     * @expected Parent element has "tabs-switcher" class
     */
    it("should render with correct container structure", () => {
      render(<TabsSwitcher activeTab="login" onTabChange={mockOnTabChange} />);

      const container = document.querySelector(".tabs-switcher");
      expect(container).toBeInTheDocument();
      expect(container?.children.length).toBe(2);
    });

    /**
     * @description Should handle keyboard navigation attributes correctly
     * @scenario Tab buttons should have proper ARIA roles for keyboard navigation
     * @expected Each tab has role="tab" and proper aria-controls reference
     */
    it("should handle keyboard navigation attributes correctly", () => {
      render(<TabsSwitcher activeTab="login" onTabChange={mockOnTabChange} />);

      const tabs = [
        { label: TABS_BTN_LABELS.login, id: "login" },
        { label: TABS_BTN_LABELS.register, id: "register" },
      ];

      tabs.forEach((tab) => {
        const tabButton = getTabButton(tab.label);
        expect(tabButton).toHaveAttribute("role", "tab");
        expect(tabButton).toHaveAttribute("aria-controls", `panel-${tab.id}`);
        expect(tabButton).toHaveAttribute("id", `tab-${tab.id}`);
      });
    });
  });
});
