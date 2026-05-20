import { renderHook } from "@testing-library/react";
import { useNavigate } from "react-router";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import { useLogout } from "@/features/auth";
import { useTheme } from "@/features/theme";
import type { DropdownMenuItem, IDropdownMenuSeparatorItem } from "@/shared/ui";

import { useProfileMenuActions } from "../useProfileMenuActions";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("react-router");
vi.mock("@/features/auth");
vi.mock("@/features/theme");

// =============================================================================
// TESTS
// =============================================================================

describe("useProfileMenuActions", () => {
  const mockNavigate = vi.fn();
  const mockLogout = vi.fn();
  const mockSetTheme = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();

    (useNavigate as Mock).mockReturnValue(mockNavigate);
    (useLogout as Mock).mockReturnValue({
      logout: mockLogout,
      isLoading: false,
    });
    (useTheme as Mock).mockReturnValue({
      theme: "light",
      setTheme: mockSetTheme,
    });
  });

  describe("when hook is called", () => {
    /**
     * @description Should return an array with all expected menu items including separators
     * @scenario Call useProfileMenuActions with default mocks
     * @expected Returns array containing profile, settings, separator, three theme items, separator, logout
     */
    it("should return complete menu structure", () => {
      // Arrange
      // Act
      const { result } = renderHook(() => useProfileMenuActions());
      const items = result.current;

      // Assert
      expect(items).toHaveLength(8);
      expect(items[0]).toMatchObject({
        id: "profile",
        label: "Профиль",
        disabled: true,
      });
      expect(items[1]).toMatchObject({
        id: "settings",
        label: "Настройки",
        disabled: true,
      });
      expect(items[2]).toHaveProperty("type", "separator");
      expect(items[3]).toMatchObject({
        id: "theme-light",
        label: "Светлая",
        icon: "sun",
      });
      expect(items[4]).toMatchObject({
        id: "theme-dark",
        label: "Тёмная",
        icon: "moon",
      });
      expect(items[5]).toMatchObject({
        id: "theme-system",
        label: "Системная",
        icon: "monitor",
      });
      expect(items[6]).toHaveProperty("type", "separator");
      expect(items[7]).toMatchObject({
        id: "logout",
        label: "Выйти",
        icon: "logout",
        isDanger: true,
      });
    });

    /**
     * @description Should add separator only when there are existing items
     * @scenario Profile and settings items are added, then addSeparator is called
     * @expected Separator appears after first two items
     */
    it("should insert separators correctly", () => {
      // Arrange
      // Act
      const { result } = renderHook(() => useProfileMenuActions());
      const items = result.current;

      // Assert
      expect((items[2] as IDropdownMenuSeparatorItem).type).toBe("separator");
      expect((items[6] as IDropdownMenuSeparatorItem).type).toBe("separator");
    });
  });

  describe("when current theme changes", () => {
    /**
     * @description Should mark active theme item with "is-active" class and disable it
     * @scenario Mock currentTheme as "dark"
     * @expected Theme item with id "theme-dark" has classNames containing "is-active" and disabled: true;
     *          other theme items have classNames empty string and disabled false
     */
    it("should add active class and disable the currently active theme", () => {
      // Arrange
      (useTheme as Mock).mockReturnValue({
        theme: "dark",
        setTheme: mockSetTheme,
      });

      // Act
      const { result } = renderHook(() => useProfileMenuActions());
      const items = result.current;

      // Assert
      const darkThemeItem = items[4]; // index of dark theme
      expect(darkThemeItem).toMatchObject({
        id: "theme-dark",
        classNames: "is-active",
        disabled: true,
      });

      const lightThemeItem = items[3];
      expect(lightThemeItem).toMatchObject({
        id: "theme-light",
        classNames: "",
        disabled: false,
      });
    });
  });

  describe("when theme item is clicked", () => {
    /**
     * @description Should call setTheme with correct theme id when theme item is clicked
     * @scenario User clicks on "light" theme menu item
     * @expected setTheme is called with "light"
     */
    it('should call setTheme with "light" when light theme is clicked', () => {
      // Arrange
      const { result } = renderHook(() => useProfileMenuActions());
      const items = result.current;
      const lightThemeItem = items[3] as DropdownMenuItem<null>;

      // Act
      if (lightThemeItem && "onClick" in lightThemeItem) {
        lightThemeItem.onClick(null);
      }

      // Assert
      expect(mockSetTheme).toHaveBeenCalledWith("light");
    });

    /**
     * @description Should call setTheme with "dark" when dark theme item is clicked
     * @scenario User clicks on "dark" theme menu item
     * @expected setTheme is called with "dark"
     */
    it('should call setTheme with "dark" when dark theme is clicked', () => {
      // Arrange
      const { result } = renderHook(() => useProfileMenuActions());
      const items = result.current;
      const darkThemeItem = items[4] as DropdownMenuItem<null>;

      // Act
      if (darkThemeItem && "onClick" in darkThemeItem) {
        darkThemeItem.onClick(null);
      }

      // Assert
      expect(mockSetTheme).toHaveBeenCalledWith("dark");
    });
  });

  describe("when logout mutation is loading", () => {
    /**
     * @description Should disable logout button when isLoading is true
     * @scenario Mock useLogout to return isLoading = true
     * @expected Logout item has disabled = true
     */
    it("should set disabled=true on logout item when logout is loading", () => {
      // Arrange
      (useLogout as Mock).mockReturnValue({
        logout: mockLogout,
        isLoading: true,
      });

      // Act
      const { result } = renderHook(() => useProfileMenuActions());
      const items = result.current;
      const logoutItem = items[7] as DropdownMenuItem<null>;

      // Assert
      expect(logoutItem).toMatchObject({ id: "logout", disabled: true });
    });

    /**
     * @description Should keep logout button enabled when isLoading is false
     * @scenario Mock useLogout to return isLoading = false
     * @expected Logout item has disabled = false
     */
    it("should set disabled=false on logout item when logout is not loading", () => {
      // Arrange
      (useLogout as Mock).mockReturnValue({
        logout: mockLogout,
        isLoading: false,
      });

      // Act
      const { result } = renderHook(() => useProfileMenuActions());
      const items = result.current;
      const logoutItem = items[7] as DropdownMenuItem<null>;

      // Assert
      expect(logoutItem).toMatchObject({ id: "logout", disabled: false });
    });
  });

  describe("when logout is clicked", () => {
    /**
     * @description Should call the logout function from useLogout when logout item is clicked
     * @scenario User clicks on logout menu item
     * @expected logout mock function is called exactly once
     */
    it("should call logout function on logout item click", () => {
      // Arrange
      const { result } = renderHook(() => useProfileMenuActions());
      const items = result.current;
      const logoutItem = items[7] as DropdownMenuItem<null>;

      // Act
      if (logoutItem && "onClick" in logoutItem) {
        logoutItem.onClick(null);
      }

      // Assert
      expect(mockLogout).toHaveBeenCalledTimes(1);
    });
  });

  describe("when profile or settings are clicked despite being disabled", () => {
    /**
     * @description Should have disabled=true for profile item
     * @scenario Check profile item properties
     * @expected disabled is true, label and icon are present
     */
    it("should have disabled=true for profile item", () => {
      // Arrange
      const { result } = renderHook(() => useProfileMenuActions());
      const items = result.current;
      const profileItem = items[0] as DropdownMenuItem<null>;

      // Assert
      expect(profileItem).toMatchObject({ id: "profile", disabled: true });
    });

    /**
     * @description Should have disabled=true for settings item
     * @scenario Check settings item properties
     * @expected disabled is true, label and icon are present
     */
    it("should have disabled=true for settings item", () => {
      // Arrange
      const { result } = renderHook(() => useProfileMenuActions());
      const items = result.current;
      const settingsItem = items[1] as DropdownMenuItem<null>;

      // Assert
      expect(settingsItem).toMatchObject({
        id: "settings",
        disabled: true,
        label: "Настройки",
        icon: "lock",
      });
    });
  });

  describe("when profile or settings items are clicked", () => {
    /**
     * @description Should call navigate with '/profile' when profile item onClick is triggered
     * @scenario Directly invoke onClick callback from profile menu item
     * @expected navigate is called with '/profile'
     */
    it('should call navigate with "/profile" when profile item onClick is triggered', () => {
      // Arrange
      const { result } = renderHook(() => useProfileMenuActions());
      const items = result.current;
      const profileItem = items[0] as DropdownMenuItem<null>;

      // Act
      if ("onClick" in profileItem) {
        profileItem.onClick(null);
      }

      // Assert
      expect(mockNavigate).toHaveBeenCalledWith("/profile");
    });

    /**
     * @description Should call navigate with '/settings' when settings item onClick is triggered
     * @scenario Directly invoke onClick callback from settings menu item
     * @expected navigate is called with '/settings'
     */
    it('should call navigate with "/settings" when settings item onClick is triggered', () => {
      // Arrange
      const { result } = renderHook(() => useProfileMenuActions());
      const items = result.current;
      const settingsItem = items[1] as DropdownMenuItem<null>;

      // Act
      if ("onClick" in settingsItem) {
        settingsItem.onClick(null);
      }

      // Assert
      expect(mockNavigate).toHaveBeenCalledWith("/settings");
    });
  });
});
