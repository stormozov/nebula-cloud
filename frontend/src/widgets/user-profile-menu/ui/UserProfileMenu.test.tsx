import { render, screen } from "@testing-library/react";
import { useSelector } from "react-redux";
import { beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import { useMediaQuery } from "@/shared/hooks";

import { useProfileMenuActions } from "../lib/useProfileMenuActions";
import { UserProfileMenu } from "./UserProfileMenu";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("react-redux");
vi.mock("@/shared/hooks");
vi.mock("../lib/useProfileMenuActions");
vi.mock("@/shared/ui", () => ({
  Avatar: vi.fn(({ alt, size, className }) => (
    <div
      data-testid="avatar"
      data-size={size}
      data-alt={alt}
      className={className}
    />
  )),
  Badge: vi.fn(({ children, position, className }) => (
    <div data-testid="badge" data-position={position} className={className}>
      {children}
    </div>
  )),
  Button: vi.fn(({ children, ...props }) => (
    <button data-testid="trigger-button" {...props}>
      {children}
    </button>
  )),
  DropdownMenu: vi.fn(({ trigger, items, placement }) => (
    <div data-testid="dropdown-menu" data-placement={placement}>
      {trigger}
      <span data-testid="items-length">{items.length}</span>
    </div>
  )),
}));

// =============================================================================
// TESTS
// =============================================================================

describe("UserProfileMenu", () => {
  const mockActions = [{ id: "mock-action" }];
  const mockUser = {
    fullName: "John Doe",
    username: "johndoe",
    isStaff: true,
  };

  beforeEach(() => {
    vi.clearAllMocks();

    (useSelector as unknown as Mock).mockReturnValue(mockUser);
    (useMediaQuery as Mock).mockReturnValue(false);
    (useProfileMenuActions as Mock).mockReturnValue(mockActions);
  });

  describe("when user is not authenticated", () => {
    /**
     * @description Should render nothing when user is not present in Redux store
     * @scenario useSelector returns null
     * @expected Component returns null, no DOM elements rendered
     */
    it("should return null when user is falsy", () => {
      // Arrange
      (useSelector as unknown as Mock).mockReturnValue(null);

      // Act
      const { container } = render(<UserProfileMenu />);

      // Assert
      expect(container).toBeEmptyDOMElement();
    });
  });

  describe("when user is authenticated", () => {
    /**
     * @description Should render dropdown menu with trigger button containing avatar and user name
     * @scenario User exists, desktop view (not mobile)
     * @expected DropdownMenu is rendered with trigger button showing avatar and fullName
     */
    it("should render dropdown menu with trigger button containing avatar and fullName", () => {
      // Arrange
      // Act
      render(<UserProfileMenu />);

      // Assert
      expect(screen.getByTestId("dropdown-menu")).toBeInTheDocument();
      expect(screen.getByTestId("trigger-button")).toBeInTheDocument();
      expect(screen.getByTestId("avatar")).toBeInTheDocument();
      expect(screen.getByText("John Doe")).toBeInTheDocument();
    });

    /**
     * @description Should pass correct items and placement to DropdownMenu
     * @scenario useProfileMenuActions returns mockActions
     * @expected DropdownMenu is called with items=mockActions, item=null, placement="bottom-end"
     */
    it("should pass actions, null item and bottom-end placement to DropdownMenu", async () => {
      // Arrange
      const { DropdownMenu } = await import("@/shared/ui");

      // Act
      render(<UserProfileMenu />);

      // Assert
      expect(DropdownMenu).toHaveBeenCalledWith(
        expect.objectContaining({
          items: mockActions,
          item: null,
          placement: "bottom-end",
        }),
        undefined,
      );
    });

    /**
     * @description Should display badge with "Админ" text when user.isStaff is true and not on mobile
     * @scenario user.isStaff = true, isMobile = false
     * @expected Badge component is rendered with "Админ" text
     */
    it('should render badge with "Админ" when user is staff and not on mobile', () => {
      // Arrange
      (useMediaQuery as Mock).mockReturnValue(false);

      // Act
      render(<UserProfileMenu />);

      // Assert
      expect(screen.getByTestId("badge")).toBeInTheDocument();
      expect(screen.getByText("Админ")).toBeInTheDocument();
    });

    /**
     * @description Should not render badge when user.isStaff is false
     * @scenario user.isStaff = false
     * @expected Badge component is not rendered
     */
    it("should not render badge when user is not staff", () => {
      // Arrange
      (useSelector as unknown as Mock).mockReturnValue({
        ...mockUser,
        isStaff: false,
      });

      // Act
      render(<UserProfileMenu />);

      // Assert
      expect(screen.queryByTestId("badge")).not.toBeInTheDocument();
    });

    /**
     * @description Should use username when fullName is not available
     * @scenario user has username but no fullName
     * @expected Displayed name is username
     */
    it("should display username when fullName is missing", () => {
      // Arrange
      (useSelector as unknown as Mock).mockReturnValue({
        username: "janedoe",
        isStaff: false,
      });

      // Act
      render(<UserProfileMenu />);

      // Assert
      expect(screen.getByText("janedoe")).toBeInTheDocument();
    });

    /**
     * @description Should not display badge on mobile even if user is staff
     * @scenario user.isStaff = true, isMobile = true
     * @expected Badge is not rendered
     */
    it("should not render badge on mobile when user is staff", () => {
      // Arrange
      (useMediaQuery as Mock).mockReturnValue(true);

      // Act
      render(<UserProfileMenu />);

      // Assert
      expect(screen.queryByTestId("badge")).not.toBeInTheDocument();
    });

    /**
     * @description Should pass correct size to Avatar based on mobile state
     * @scenario isMobile = true → size="md"
     * @expected Avatar receives size "md"
     */
    it('should pass size "md" to Avatar when on mobile', async () => {
      // Arrange
      const { Avatar } = await import("@/shared/ui");
      (useMediaQuery as Mock).mockReturnValue(true);

      // Act
      render(<UserProfileMenu />);

      // Assert
      expect(Avatar).toHaveBeenCalledWith(
        expect.objectContaining({ size: "md" }),
        undefined,
      );
    });

    /**
     * @description Should pass correct size to Avatar based on mobile state
     * @scenario isMobile = false → size="sm"
     * @expected Avatar receives size "sm"
     */
    it('should pass size "sm" to Avatar when not on mobile', async () => {
      // Arrange
      const { Avatar } = await import("@/shared/ui");
      (useMediaQuery as Mock).mockReturnValue(false);

      // Act
      render(<UserProfileMenu />);

      // Assert
      expect(Avatar).toHaveBeenCalledWith(
        expect.objectContaining({ size: "sm" }),
        undefined,
      );
    });

    /**
     * @description Should use empty string as avatar src and correct alt text
     * @scenario User has fullName
     * @expected Avatar receives src="" and alt=fullName
     */
    it("should pass empty src and user fullName as alt to Avatar", async () => {
      // Arrange
      const { Avatar } = await import("@/shared/ui");

      // Act
      render(<UserProfileMenu />);

      // Assert
      expect(Avatar).toHaveBeenCalledWith(
        expect.objectContaining({
          src: "",
          alt: "John Doe",
        }),
        undefined,
      );
    });

    /**
     * @description Should set correct aria-label on trigger button
     * @scenario Any authenticated user
     * @expected Button receives aria-label="Меню пользователя"
     */
    it('should set aria-label "Меню пользователя" on trigger button', async () => {
      // Arrange
      const { Button } = await import("@/shared/ui");

      // Act
      render(<UserProfileMenu />);

      // Assert
      expect(Button).toHaveBeenCalledWith(
        expect.objectContaining({
          "aria-label": "Меню пользователя",
        }),
        undefined,
      );
    });
  });
});
