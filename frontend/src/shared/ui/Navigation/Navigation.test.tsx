import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import { useAppSelector } from "@/app/store/hooks";
import { selectIsStaff } from "@/entities/user";
import { useMediaQuery } from "@/shared/hooks";

import { type INavItem, Navigation } from "../Navigation";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("@/app/store/hooks", () => ({
  useAppSelector: vi.fn(),
}));

vi.mock("@/entities/user", () => ({
  selectIsStaff: vi.fn(),
}));

vi.mock("@/shared/hooks", () => ({
  useMediaQuery: vi.fn(),
}));

vi.mock("@/shared/ui", () => ({
  Button: vi.fn(({ children, onClick, className }) => (
    <button
      type="button"
      data-testid="mock-button"
      className={className}
      onClick={onClick}
    >
      {children}
    </button>
  )),
  DropdownMenu: vi.fn(({ trigger, items, isOpen, placement }) => (
    <div
      data-testid="mock-dropdown-menu"
      data-isopen={isOpen}
      data-placement={placement}
    >
      {trigger}
      {isOpen && <div data-testid="dropdown-items">{items}</div>}
    </div>
  )),
  Icon: vi.fn(({ name }) => <span data-testid={`icon-${name}`} />),
}));

vi.mock("react-router", async () => {
  const actual = await vi.importActual("react-router");
  return {
    ...actual,
    NavLink: vi.fn(({ to, children, className, onClick }) => {
      const computedClassName =
        typeof className === "function"
          ? className({ isActive: false })
          : className;
      return (
        <a
          href={to}
          data-testid={`nav-link-${to}`}
          className={computedClassName}
          onClick={onClick}
        >
          {children}
        </a>
      );
    }),
  };
});

// =============================================================================
// TESTS
// =============================================================================

describe("Navigation", () => {
  const mockUseAppSelector = useAppSelector as Mock;
  const mockSelectIsStaff = selectIsStaff as Mock;
  const mockUseMediaQuery = useMediaQuery as Mock;

  const defaultItems: INavItem[] = [
    {
      to: "/admin/dashboard",
      icon: "dashboard",
      label: "Админ-панель",
      roles: ["admin"],
      withIcon: true,
    },
    {
      to: "/disk",
      icon: "folder",
      label: "Мой диск",
      roles: ["user", "admin"],
      withIcon: true,
    },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    // Mock window.location.pathname
    Object.defineProperty(window, "location", {
      value: { pathname: "/" },
      writable: true,
    });
  });

  const renderWithRouter = (ui: React.ReactElement, initialEntries = ["/"]) => {
    return render(
      <MemoryRouter initialEntries={initialEntries}>{ui}</MemoryRouter>,
    );
  };

  describe("when user role is admin", () => {
    beforeEach(() => {
      mockSelectIsStaff.mockReturnValue(true);
      mockUseAppSelector.mockImplementation((selector) => {
        if (selector === selectIsStaff) return true;
        return undefined;
      });
    });

    /**
     * @description Should filter navigation items to show only admin-accessible links
     * @scenario User is admin, default items contain both admin and user roles
     * @expected Both "/admin/dashboard" and "/disk" are visible
     */
    it("should show both admin and user items for admin role", () => {
      // Arrange
      mockUseMediaQuery.mockReturnValue(false); // desktop

      // Act
      renderWithRouter(<Navigation items={defaultItems} />);

      // Assert
      expect(
        screen.getByTestId("nav-link-/admin/dashboard"),
      ).toBeInTheDocument();
      expect(screen.getByTestId("nav-link-/disk")).toBeInTheDocument();
    });
  });

  describe("when user role is regular user", () => {
    beforeEach(() => {
      mockSelectIsStaff.mockReturnValue(false);
      mockUseAppSelector.mockImplementation((selector) => {
        if (selector === selectIsStaff) return false;
        return undefined;
      });
    });

    /**
     * @description Should filter out admin-only items when user is not staff
     * @scenario User role is 'user', navigation items include admin-restricted link
     * @expected Only "/disk" is visible, admin dashboard is filtered out
     */
    it("should hide admin-only items for non-admin user", () => {
      // Arrange
      const itemsForUser: INavItem[] = [
        {
          to: "/admin/dashboard",
          icon: "dashboard",
          label: "Админ-панель",
          roles: ["admin"],
          withIcon: true,
        },
        {
          to: "/disk",
          icon: "folder",
          label: "Мой диск",
          roles: ["user", "admin"],
          withIcon: true,
        },
        {
          to: "/profile",
          icon: "person",
          label: "Профиль",
          roles: ["user"],
          withIcon: true,
        },
      ];
      mockUseMediaQuery.mockReturnValue(false);
      mockSelectIsStaff.mockReturnValue(false); // role = "user"

      // Act
      renderWithRouter(<Navigation items={itemsForUser} />);

      // Assert
      expect(
        screen.queryByTestId("nav-link-/admin/dashboard"),
      ).not.toBeInTheDocument();
      expect(screen.getByTestId("nav-link-/disk")).toBeInTheDocument();
      expect(screen.getByTestId("nav-link-/profile")).toBeInTheDocument();
    });
  });

  describe("when visible items count is 1 or less", () => {
    beforeEach(() => {
      mockSelectIsStaff.mockReturnValue(false);
      mockUseAppSelector.mockImplementation((selector) => {
        if (selector === selectIsStaff) return false;
        return undefined;
      });
    });

    /**
     * @description Should return null when only one navigation item is visible after filtering
     * @scenario User is regular user and only one item (e.g., only "/disk") is provided
     * @expected Component renders nothing (null)
     */
    it("should return null when only one visible item exists", () => {
      // Arrange
      const singleItem: INavItem[] = [
        { to: "/disk", label: "Мой диск", roles: ["user"], withIcon: true },
      ];
      mockUseMediaQuery.mockReturnValue(false);

      // Act
      const { container } = renderWithRouter(<Navigation items={singleItem} />);

      // Assert
      expect(container).toBeEmptyDOMElement();
    });

    /**
     * @description Should return null when no visible items after filtering
     * @scenario User is regular user but all items require admin role
     * @expected Component renders null
     */
    it("should return null when no visible items", () => {
      // Arrange
      const adminOnlyItems: INavItem[] = [
        { to: "/admin", label: "Admin", roles: ["admin"] },
      ];
      mockUseMediaQuery.mockReturnValue(false);

      // Act
      const { container } = renderWithRouter(
        <Navigation items={adminOnlyItems} />,
      );

      // Assert
      expect(container).toBeEmptyDOMElement();
    });
  });

  describe("when on mobile viewport", () => {
    beforeEach(() => {
      mockSelectIsStaff.mockReturnValue(true);
      mockUseAppSelector.mockImplementation((selector) => {
        if (selector === selectIsStaff) return true;
        return undefined;
      });
      mockUseMediaQuery.mockReturnValue(true); // mobile
    });

    /**
     * @description Should render DropdownMenu with trigger button on mobile
     * @scenario isMobile true, visible items exist
     * @expected DropdownMenu component rendered with trigger button containing menu icon
     */
    it("should render dropdown menu with trigger button on mobile", () => {
      // Arrange & Act
      renderWithRouter(<Navigation items={defaultItems} />);

      // Assert
      expect(screen.getByTestId("mock-dropdown-menu")).toBeInTheDocument();
      expect(screen.getByTestId("mock-button")).toBeInTheDocument();
      expect(screen.getByTestId("icon-menu")).toBeInTheDocument();
    });

    /**
     * @description Should pass isOpen and onOpenChange state to DropdownMenu
     * @scenario User clicks trigger button to open dropdown
     * @expected isOpen prop toggles, dropdown items appear/hide accordingly
     */
    it("should toggle dropdown when trigger button is clicked", async () => {
      // Arrange
      const user = userEvent.setup();
      renderWithRouter(<Navigation items={defaultItems} />);

      const dropdownMenu = screen.getByTestId("mock-dropdown-menu");
      expect(dropdownMenu).toHaveAttribute("data-isopen", "false");

      // Act
      const triggerButton = screen.getByTestId("mock-button");
      await user.click(triggerButton);

      // Assert
      expect(dropdownMenu).toHaveAttribute("data-isopen", "true");
      expect(screen.getByTestId("dropdown-items")).toBeInTheDocument();

      // Act again - close
      await user.click(triggerButton);
      expect(dropdownMenu).toHaveAttribute("data-isopen", "false");
    });

    /**
     * @description Should close dropdown when a navigation link is clicked
     * @scenario Dropdown open, user clicks on a menu item
     * @expected onOpenChange called with false, dropdown closes
     */
    it("should close dropdown when nav link inside dropdown is clicked", async () => {
      // Arrange
      const user = userEvent.setup();
      renderWithRouter(<Navigation items={defaultItems} />);

      const triggerButton = screen.getByTestId("mock-button");
      await user.click(triggerButton);

      const dropdownMenu = screen.getByTestId("mock-dropdown-menu");
      expect(dropdownMenu).toHaveAttribute("data-isopen", "true");

      // Act
      const diskLink = screen.getByTestId("nav-link-/disk");
      await user.click(diskLink);

      // Assert
      expect(dropdownMenu).toHaveAttribute("data-isopen", "false");
    });

    /**
     * @description Should pass placement "bottom-end" to DropdownMenu
     * @scenario Mobile viewport active
     * @expected DropdownMenu receives placement prop equal to "bottom-end"
     */
    it('should pass placement "bottom-end" to DropdownMenu on mobile', () => {
      // Arrange & Act
      renderWithRouter(<Navigation items={defaultItems} />);

      // Assert
      const dropdownMenu = screen.getByTestId("mock-dropdown-menu");
      expect(dropdownMenu).toHaveAttribute("data-placement", "bottom-end");
    });
  });

  describe("when on desktop viewport", () => {
    beforeEach(() => {
      mockSelectIsStaff.mockReturnValue(true);
      mockUseAppSelector.mockImplementation((selector) => {
        if (selector === selectIsStaff) return true;
        return undefined;
      });
      mockUseMediaQuery.mockReturnValue(false); // desktop
    });

    /**
     * @description Should render horizontal navigation bar with NavLinks on desktop
     * @scenario isMobile false, visible items exist
     * @expected <nav> element with NavLink components for each visible item
     */
    it("should render nav element with direct NavLinks", () => {
      // Arrange & Act
      const { container } = renderWithRouter(
        <Navigation items={defaultItems} />,
      );

      // Assert
      expect(container.querySelector("nav.navigation")).toBeInTheDocument();
      expect(
        screen.getByTestId("nav-link-/admin/dashboard"),
      ).toBeInTheDocument();
      expect(screen.getByTestId("nav-link-/disk")).toBeInTheDocument();
      expect(
        screen.queryByTestId("mock-dropdown-menu"),
      ).not.toBeInTheDocument();
    });

    /**
     * @description Should apply active class when current path matches link's "to" prop
     * @scenario Desktop view, current location path is "/disk"
     * @expected NavLink for "/disk" gets "navigation__link--active" class
     */
    it("should add active class to NavLink when pathname matches", () => {
      // Arrange
      Object.defineProperty(window, "location", {
        value: { pathname: "/disk" },
        writable: true,
      });

      // Act
      renderWithRouter(<Navigation items={defaultItems} />, ["/disk"]);

      // Assert
      const diskLink = screen.getByTestId("nav-link-/disk");
      expect(diskLink).toHaveClass("navigation__link--active");

      const dashboardLink = screen.getByTestId("nav-link-/admin/dashboard");
      expect(dashboardLink).not.toHaveClass("navigation__link--active");
    });

    /**
     * @description Should render icons for items with withIcon=true
     * @scenario Desktop, item has icon and withIcon=true
     * @expected Icon component rendered with corresponding name
     */
    it("should render icon when item has icon and withIcon is true", () => {
      // Arrange & Act
      renderWithRouter(<Navigation items={defaultItems} />);

      // Assert
      expect(screen.getByTestId("icon-dashboard")).toBeInTheDocument();
      expect(screen.getByTestId("icon-folder")).toBeInTheDocument();
    });

    /**
     * @description Should not render icon if withIcon is false
     * @scenario Item has icon property but withIcon set to false
     * @expected No Icon component for that item
     */
    it("should not render icon when withIcon is false", () => {
      // Arrange
      const itemsWithAndWithoutIcon: INavItem[] = [
        {
          to: "/disk",
          label: "Мой диск",
          icon: "folder",
          withIcon: false,
          roles: ["user"],
        },
        {
          to: "/profile",
          label: "Профиль",
          icon: "person",
          withIcon: true,
          roles: ["user"],
        },
      ];

      mockSelectIsStaff.mockReturnValue(false);
      mockUseAppSelector.mockImplementation((selector) => {
        if (selector === selectIsStaff) return false;
        return undefined;
      });
      mockUseMediaQuery.mockReturnValue(false);

      // Act
      renderWithRouter(<Navigation items={itemsWithAndWithoutIcon} />);

      // Assert
      expect(screen.queryByTestId("icon-folder")).not.toBeInTheDocument();
      expect(screen.getByTestId("nav-link-/disk")).toHaveTextContent(
        "Мой диск",
      );
      expect(screen.getByTestId("icon-person")).toBeInTheDocument();
    });
  });
});
