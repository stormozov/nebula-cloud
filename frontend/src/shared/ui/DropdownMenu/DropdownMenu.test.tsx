import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DropdownMenu } from "../DropdownMenu";
import type { IDropdownMenuActionItem, IDropdownMenuProps } from "./types";

// =============================================================================
// MOCKS
// =============================================================================

vi.mock("@/shared/ui", () => ({
  Button: vi.fn(({ children, onClick, ...props }) => (
    <button data-testid="mock-button" onClick={onClick} {...props}>
      {children}
    </button>
  )),
  Icon: vi.fn(({ name, size, className }) => (
    <span data-testid={`icon-${name}`} data-size={size} className={className} />
  )),
  Divider: vi.fn(({ gap }) => <hr data-testid="divider" data-gap={gap} />),
}));

let clickOutsideCallback: (() => void) | null = null;
vi.mock("@/shared/hooks/useClickOutside", () => ({
  useClickOutside: vi.fn((_ref, callback) => {
    clickOutsideCallback = callback;
  }),
}));

vi.mock("react-dom", async () => {
  const actual = await vi.importActual("react-dom");
  return {
    ...actual,
    createPortal: vi.fn((children) => children),
  };
});

// =============================================================================
// TEST HELPERS
// =============================================================================

interface TestItem {
  id: number;
  name: string;
}

const testItem: TestItem = { id: 1, name: "Test Item" };

const createAction = (
  overrides?: Partial<IDropdownMenuActionItem<TestItem>>,
): IDropdownMenuActionItem<TestItem> => ({
  id: "action1",
  label: "Action 1",
  onClick: vi.fn(),
  ...overrides,
});

// =============================================================================
// TESTS
// =============================================================================

describe("DropdownMenu", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clickOutsideCallback = null;
  });

  describe("when rendered with triggerButtonProps", () => {
    /**
     * @description Should open menu when trigger button is clicked
     * @scenario User clicks on the trigger button
     * @expected Menu becomes visible and menu items are rendered
     */
    it("should open menu on button click", async () => {
      // Arrange
      const items = [createAction()];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open Menu" }}
          items={items}
          item={testItem}
        />,
      );

      // Act
      await userEvent.click(screen.getByTestId("mock-button"));

      // Assert
      expect(screen.getByRole("menu")).toBeInTheDocument();
      expect(screen.getByText("Action 1")).toBeInTheDocument();
    });

    /**
     * @description Should close menu when clicking outside
     * @scenario Menu is open and user clicks outside the menu
     * @expected Menu is removed from document
     */
    it("should close menu when clicking outside", async () => {
      // Arrange
      const items = [createAction()];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      await userEvent.click(screen.getByTestId("mock-button"));
      expect(screen.getByRole("menu")).toBeInTheDocument();

      // Act – вызываем колбэк clickOutside, сохранённый из мока
      clickOutsideCallback?.();

      // Assert
      await waitFor(() => {
        expect(screen.queryByRole("menu")).not.toBeInTheDocument();
      });
    });

    /**
     * @description Should call onOpenChange when menu opens and closes
     * @scenario User opens and then closes the menu
     * @expected onOpenChange is called with true then false
     */
    it("should call onOpenChange when open state changes", async () => {
      // Arrange
      const onOpenChange = vi.fn();
      const items = [createAction()];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
          onOpenChange={onOpenChange}
        />,
      );

      // Act – open
      await userEvent.click(screen.getByTestId("mock-button"));

      // Assert
      expect(onOpenChange).toHaveBeenCalledWith(true);

      // Act – close by clicking outside
      clickOutsideCallback?.();

      // Assert
      await waitFor(() => {
        expect(onOpenChange).toHaveBeenCalledWith(false);
      });
    });
  });

  // ===========================================================================

  describe("when rendered with custom trigger element", () => {
    /**
     * @description Should open menu when custom trigger is clicked
     * @scenario User clicks on the custom trigger element
     * @expected Menu becomes visible and receives keyboard handlers
     */
    it("should open menu on trigger click", async () => {
      // Arrange
      const Trigger = (
        <button type="button" data-testid="custom-trigger">
          Click
        </button>
      );
      const items = [createAction()];
      render(
        <DropdownMenu<TestItem>
          trigger={Trigger}
          items={items}
          item={testItem}
        />,
      );

      // Act
      await userEvent.click(screen.getByTestId("custom-trigger"));

      // Assert
      expect(screen.getByRole("menu")).toBeInTheDocument();
    });

    /**
     * @description Should preserve original trigger's onKeyDown handler
     * @scenario Custom trigger has its own onKeyDown, user focuses trigger and presses Enter
     * @expected Original handler is called and menu opens
     */
    it("should preserve original onKeyDown handler of custom trigger", async () => {
      // Arrange
      const originalOnKeyDown = vi.fn();
      const Trigger = (
        <button
          type="button"
          data-testid="custom-trigger"
          onKeyDown={originalOnKeyDown}
        >
          Click
        </button>
      );
      const items = [createAction()];
      render(
        <DropdownMenu<TestItem>
          trigger={Trigger}
          items={items}
          item={testItem}
        />,
      );

      // Act – focus the trigger and press Enter
      await userEvent.tab();
      expect(screen.getByTestId("custom-trigger")).toHaveFocus();
      await userEvent.keyboard("{Enter}");

      // Assert
      expect(originalOnKeyDown).toHaveBeenCalled();
      expect(screen.getByRole("menu")).toBeInTheDocument();
    });
  });

  // ===========================================================================

  describe("when used as context menu (no trigger, with position)", () => {
    /**
     * @description Should render menu at fixed position when isOpen=true and position provided
     * @scenario Component receives isOpen=true and position coordinates
     * @expected Menu element is present with fixed positioning style
     */
    it("should render menu at given position", () => {
      // Arrange
      const items = [createAction()];
      render(
        <DropdownMenu<TestItem>
          items={items}
          item={testItem}
          isOpen={true}
          position={{ x: 100, y: 200 }}
        />,
      );

      // Assert
      const menu = screen.getByRole("menu");
      expect(menu).toBeInTheDocument();
      expect(menu.style.position).toBe("fixed");
      expect(menu.style.left).toBe("100px");
      expect(menu.style.top).toBe("200px");
    });
  });

  // ===========================================================================

  describe("keyboard navigation", () => {
    /**
     * @description Should focus first enabled item when menu opens
     * @scenario Menu opens with several actions, first is enabled
     * @expected First action button receives focus
     */
    it("should focus first enabled item on open", async () => {
      // Arrange
      const items = [
        createAction({ id: "1", label: "First" }),
        createAction({ id: "2", label: "Second", disabled: true }),
        createAction({ id: "3", label: "Third" }),
      ];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      // Act
      await userEvent.click(screen.getByTestId("mock-button"));

      // Assert – получаем кнопку по роли, а не span
      const firstButton = screen.getByRole("menuitem", { name: "First" });
      expect(firstButton).toHaveFocus();
    });

    /**
     * @description Should navigate down with ArrowDown key
     * @scenario Menu open, user presses ArrowDown
     * @expected Focus moves to next enabled item
     */
    it("should move focus down on ArrowDown", async () => {
      // Arrange
      const items = [
        createAction({ id: "1", label: "First" }),
        createAction({ id: "2", label: "Second" }),
      ];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      await userEvent.click(screen.getByTestId("mock-button"));
      const firstButton = screen.getByRole("menuitem", { name: "First" });
      expect(firstButton).toHaveFocus();

      // Act
      await userEvent.keyboard("{ArrowDown}");

      // Assert
      const secondButton = screen.getByRole("menuitem", { name: "Second" });
      expect(secondButton).toHaveFocus();
    });

    /**
     * @description Should navigate up with ArrowUp key
     * @scenario Menu open, focus on second item, user presses ArrowUp
     * @expected Focus moves to first enabled item
     */
    it("should move focus up on ArrowUp", async () => {
      // Arrange
      const items = [
        createAction({ id: "1", label: "First" }),
        createAction({ id: "2", label: "Second" }),
      ];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      await userEvent.click(screen.getByTestId("mock-button"));
      await userEvent.keyboard("{ArrowDown}"); // focus Second
      const secondButton = screen.getByRole("menuitem", { name: "Second" });
      expect(secondButton).toHaveFocus();

      // Act
      await userEvent.keyboard("{ArrowUp}");

      // Assert
      const firstButton = screen.getByRole("menuitem", { name: "First" });
      expect(firstButton).toHaveFocus();
    });

    /**
     * @description Should skip disabled items when navigating with arrows
     * @scenario Menu has disabled item between enabled ones
     * @expected Arrow navigation jumps over disabled item
     */
    it("should skip disabled items on arrow navigation", async () => {
      // Arrange
      const items = [
        createAction({ id: "1", label: "First" }),
        createAction({ id: "2", label: "Disabled", disabled: true }),
        createAction({ id: "3", label: "Third" }),
      ];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      await userEvent.click(screen.getByTestId("mock-button"));
      const firstButton = screen.getByRole("menuitem", { name: "First" });
      expect(firstButton).toHaveFocus();

      // Act – ArrowDown should skip disabled and go to Third
      await userEvent.keyboard("{ArrowDown}");

      // Assert
      const thirdButton = screen.getByRole("menuitem", { name: "Third" });
      expect(thirdButton).toHaveFocus();
    });

    /**
     * @description Should select action with Enter key
     * @scenario Menu open, focus on enabled action, user presses Enter
     * @expected onClick handler is called and menu closes
     */
    it("should select action with Enter key", async () => {
      // Arrange
      const onClick = vi.fn();
      const items = [createAction({ onClick })];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      await userEvent.click(screen.getByTestId("mock-button"));
      const actionButton = screen.getByRole("menuitem", { name: "Action 1" });
      expect(actionButton).toHaveFocus();

      // Act
      await userEvent.keyboard("{Enter}");

      // Assert
      expect(onClick).toHaveBeenCalledWith(testItem);
      await waitFor(() => {
        expect(screen.queryByRole("menu")).not.toBeInTheDocument();
      });
    });

    /**
     * @description Should close menu on Escape key
     * @scenario Menu open, user presses Escape
     * @expected Menu closes and focus returns to trigger
     */
    it("should close menu on Escape", async () => {
      // Arrange
      const items = [createAction()];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      await userEvent.click(screen.getByTestId("mock-button"));
      expect(screen.getByRole("menu")).toBeInTheDocument();

      // Act
      await userEvent.keyboard("{Escape}");

      // Assert
      await waitFor(() => {
        expect(screen.queryByRole("menu")).not.toBeInTheDocument();
      });
      expect(screen.getByTestId("mock-button")).toHaveFocus();
    });
  });

  // ===========================================================================

  describe("action items", () => {
    /**
     * @description Should call onClick with the provided item data
     * @scenario User clicks on an action button
     * @expected onClick handler receives the item object
     */
    it("should call onClick with item data when clicked", async () => {
      // Arrange
      const onClick = vi.fn();
      const items = [createAction({ onClick })];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      await userEvent.click(screen.getByTestId("mock-button"));

      // Act
      await userEvent.click(screen.getByRole("menuitem", { name: "Action 1" }));

      // Assert
      expect(onClick).toHaveBeenCalledWith(testItem);
    });

    /**
     * @description Should not call onClick when action is disabled
     * @scenario Action has disabled=true and user clicks on it
     * @expected onClick is not called and menu remains open
     */
    it("should not call onClick for disabled action", async () => {
      // Arrange
      const onClick = vi.fn();
      const items = [createAction({ onClick, disabled: true })];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      await userEvent.click(screen.getByTestId("mock-button"));
      const disabledButton = screen.getByRole("menuitem", { name: "Action 1" });

      // Act
      await userEvent.click(disabledButton);

      // Assert
      expect(onClick).not.toHaveBeenCalled();
      expect(screen.getByRole("menu")).toBeInTheDocument(); // menu stays open
    });

    /**
     * @description Should evaluate disabled function with current item
     * @scenario Action.disabled is a function that returns true based on item
     * @expected Button is disabled and onClick not called
     */
    it("should evaluate disabled function with item", async () => {
      // Arrange
      const onClick = vi.fn();
      const disabledFn = vi.fn((item: TestItem) => item.id === 1);
      const items = [createAction({ onClick, disabled: disabledFn })];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      await userEvent.click(screen.getByTestId("mock-button"));
      const button = screen.getByRole("menuitem", { name: "Action 1" });

      // Assert
      expect(disabledFn).toHaveBeenCalledWith(testItem);
      expect(button).toHaveAttribute("aria-disabled", "true");
      expect(button).toBeDisabled();

      // Act
      await userEvent.click(button);
      expect(onClick).not.toHaveBeenCalled();
    });

    /**
     * @description Should render icon when provided
     * @scenario Action has icon name
     * @expected Icon component is rendered with correct name
     */
    it("should render icon if provided", async () => {
      // Arrange
      const items = [createAction({ icon: "edit" })];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      await userEvent.click(screen.getByTestId("mock-button"));

      // Assert
      expect(screen.getByTestId("icon-edit")).toBeInTheDocument();
    });

    /**
     * @description Should apply danger class when isDanger=true
     * @scenario Action has isDanger flag
     * @expected Button has class 'dropdown-menu__item--danger'
     */
    it("should apply danger class when isDanger is true", async () => {
      // Arrange
      const items = [createAction({ isDanger: true })];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      await userEvent.click(screen.getByTestId("mock-button"));
      const button = screen.getByRole("menuitem", { name: "Action 1" });

      // Assert
      expect(button.className).toContain("dropdown-menu__item--danger");
    });
  });

  // ===========================================================================

  describe("separators and custom elements", () => {
    /**
     * @description Should render Divider for separator items
     * @scenario Items array contains separator object with type 'separator'
     * @expected Divider component is rendered
     */
    it("should render Divider for separator item", async () => {
      // Arrange
      const items: IDropdownMenuProps<TestItem>["items"] = [
        createAction({ id: "1", label: "Action" }),
        { type: "separator", id: "sep1" },
        createAction({ id: "2", label: "Another" }),
      ];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      await userEvent.click(screen.getByTestId("mock-button"));

      // Assert
      expect(screen.getByTestId("divider")).toBeInTheDocument();
    });

    /**
     * @description Should render custom React element as menu item
     * @scenario Items array contains React element
     * @expected Custom element appears in the menu
     */
    it("should render custom React element as menu item", async () => {
      // Arrange
      const CustomItem = <div data-testid="custom-item">Custom</div>;
      const items: IDropdownMenuProps<TestItem>["items"] = [
        createAction(),
        CustomItem,
      ];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
        />,
      );

      await userEvent.click(screen.getByTestId("mock-button"));

      // Assert
      expect(screen.getByTestId("custom-item")).toBeInTheDocument();
    });
  });

  // ===========================================================================

  describe("controlled mode", () => {
    /**
     * @description Should respect isOpen prop in controlled mode
     * @scenario Component receives isOpen=true and no onOpenChange
     * @expected Menu is rendered and clicking trigger does not close it
     */
    it("should respect isOpen prop and not react to internal toggle", async () => {
      // Arrange
      const items = [createAction()];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
          isOpen={true}
        />,
      );

      // Assert menu is open
      expect(screen.getByRole("menu")).toBeInTheDocument();

      // Act – click trigger (should not close because controlled)
      await userEvent.click(screen.getByTestId("mock-button"));

      // Assert – menu still open
      expect(screen.getByRole("menu")).toBeInTheDocument();
    });

    /**
     * @description Should call onOpenChange when controlled menu would close
     * @scenario Controlled menu is open, user clicks outside
     * @expected onOpenChange is called with false
     */
    it("should call onOpenChange on outside click in controlled mode", () => {
      // Arrange
      const onOpenChange = vi.fn();
      const items = [createAction()];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
          isOpen={true}
          onOpenChange={onOpenChange}
        />,
      );

      // Act – simulate click outside
      clickOutsideCallback?.();

      // Assert
      expect(onOpenChange).toHaveBeenCalledWith(false);
      expect(screen.getByRole("menu")).toBeInTheDocument();
    });
  });

  // ===========================================================================

  describe("context menu prevention", () => {
    /**
     * @description Should prevent default browser context menu and stop propagation
     * @scenario User right-clicks on the dropdown menu
     * @expected preventDefault and stopPropagation are called on the event
     */
    it("should prevent default context menu and stop propagation on menu", () => {
      // Arrange
      const items = [createAction()];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open" }}
          items={items}
          item={testItem}
          isOpen={true}
        />,
      );

      const menu = screen.getByRole("menu");
      const event = new MouseEvent("contextmenu", {
        bubbles: true,
        cancelable: true,
      });
      const preventDefaultSpy = vi.spyOn(event, "preventDefault");
      const stopPropagationSpy = vi.spyOn(event, "stopPropagation");

      // Act
      menu.dispatchEvent(event);

      // Assert
      expect(preventDefaultSpy).toHaveBeenCalled();
      expect(stopPropagationSpy).toHaveBeenCalled();
    });
  });

  // ===========================================================================

  describe("triggerButtonProps keydown handling", () => {
    /**
     * @description Should call custom onKeyDown handler when provided and prevent propagation for Enter/Space
     * @scenario User presses Enter or Space on trigger button with custom onKeyDown
     * @expected Custom onKeyDown is called and event propagation is stopped for Enter/Space
     */
    it("should call custom onKeyDown and stop propagation for Enter/Space", async () => {
      // Arrange
      const onKeyDown = vi.fn();
      const items = [createAction()];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open", onKeyDown }}
          items={items}
          item={testItem}
        />,
      );

      const button = screen.getByTestId("mock-button");

      // Act – press Enter
      const enterEvent = new KeyboardEvent("keydown", {
        key: "Enter",
        bubbles: true,
      });
      const enterStopPropagationSpy = vi.spyOn(enterEvent, "stopPropagation");
      button.dispatchEvent(enterEvent);

      // Assert
      expect(onKeyDown).toHaveBeenCalled();
      expect(enterStopPropagationSpy).toHaveBeenCalled();

      // Act – press Space
      vi.clearAllMocks();
      const spaceEvent = new KeyboardEvent("keydown", {
        key: " ",
        bubbles: true,
      });
      const spaceStopPropagationSpy = vi.spyOn(spaceEvent, "stopPropagation");
      button.dispatchEvent(spaceEvent);

      // Assert
      expect(onKeyDown).toHaveBeenCalled();
      expect(spaceStopPropagationSpy).toHaveBeenCalled();
    });

    /**
     * @description Should not stop propagation for other keys
     * @scenario User presses a non-Enter/Space key on trigger button
     * @expected Custom onKeyDown is called but stopPropagation is not called
     */
    it("should not stop propagation for non-Enter/Space keys", async () => {
      // Arrange
      const onKeyDown = vi.fn();
      const items = [createAction()];
      render(
        <DropdownMenu<TestItem>
          triggerButtonProps={{ children: "Open", onKeyDown }}
          items={items}
          item={testItem}
        />,
      );

      const button = screen.getByTestId("mock-button");

      // Act – press ArrowDown
      const event = new KeyboardEvent("keydown", {
        key: "ArrowDown",
        bubbles: true,
      });
      const stopPropagationSpy = vi.spyOn(event, "stopPropagation");
      button.dispatchEvent(event);

      // Assert
      expect(onKeyDown).toHaveBeenCalled();
      expect(stopPropagationSpy).not.toHaveBeenCalled();
    });
  });
});
