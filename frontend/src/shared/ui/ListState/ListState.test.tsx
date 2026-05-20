import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ListState } from "./ListState";
import type { IListStatesRenders } from "./types";

vi.mock("../Icon", () => ({
  Icon: ({
    name,
    size,
    className,
  }: {
    name: string;
    size: number;
    className?: string;
  }) => (
    <div
      data-testid="mock-icon"
      data-name={name}
      data-size={size}
      className={className}
    >
      Mock Icon: {name}
    </div>
  ),
}));

describe("ListState", () => {
  const defaultChildren = (
    <div data-testid="children-content">Actual list content</div>
  );

  describe("when no state conditions are active", () => {
    /**
     * @description Should render children when loading is false, error is null, and itemsCount > 0
     * @scenario Pass children, states: { isLoading: false, error: null, itemsCount: 1 }
     * @expected Children content is present in the document
     */
    it("should render children when loading false, error null, and itemsCount > 0", () => {
      // Arrange
      const states = {
        isLoading: false,
        error: null,
        itemsCount: 1,
      };

      // Act
      render(<ListState states={states}>{defaultChildren}</ListState>);

      // Assert
      expect(screen.getByTestId("children-content")).toBeInTheDocument();
    });

    /**
     * @description Should render children when states object is undefined
     * @scenario Render ListState without `states` prop
     * @expected Children content is displayed
     */
    it("should render children when states prop is undefined", () => {
      // Arrange & Act
      render(<ListState>{defaultChildren}</ListState>);

      // Assert
      expect(screen.getByTestId("children-content")).toBeInTheDocument();
    });
  });

  // ===========================================================================

  describe("when loading state is active", () => {
    /**
     * @description Should render default loading UI when isLoading true and no custom renderLoading provided
     * @scenario Set states: { isLoading: true }
     * @expected Default loading message and icon are displayed, children are not rendered
     */
    it("should render default loading UI when isLoading true", () => {
      // Arrange
      const states = { isLoading: true };

      // Act
      render(<ListState states={states}>{defaultChildren}</ListState>);

      // Assert
      expect(screen.getByText("Загрузка...")).toBeInTheDocument();
      expect(screen.getByTestId("mock-icon")).toHaveAttribute(
        "data-name",
        "cloudLoading",
      );
      expect(screen.queryByTestId("children-content")).not.toBeInTheDocument();
    });

    /**
     * @description Should render custom loading UI when renderLoading is provided
     * @scenario Pass renders.renderLoading that returns custom content
     * @expected Custom loading content is displayed, default UI is not present
     */
    it("should render custom loading UI when renderLoading is provided", () => {
      // Arrange
      const states = { isLoading: true };
      const renders: IListStatesRenders = {
        renderLoading: () => (
          <div data-testid="custom-loader">Custom loading spinner</div>
        ),
      };

      // Act
      render(
        <ListState states={states} renders={renders}>
          {defaultChildren}
        </ListState>,
      );

      // Assert
      expect(screen.getByTestId("custom-loader")).toBeInTheDocument();
      expect(screen.queryByText("Загрузка...")).not.toBeInTheDocument();
      expect(screen.queryByTestId("children-content")).not.toBeInTheDocument();
    });
  });

  // ===========================================================================

  describe("when error state is active", () => {
    /**
     * @description Should render default error UI when error is a string and no custom renderError provided
     * @scenario Set states: { error: "Network failure" }
     * @expected Default error message with icon and error text are displayed, children not rendered
     */
    it("should render default error UI when error is a string", () => {
      // Arrange
      const errorMessage = "Network failure";
      const states = { error: errorMessage };

      // Act
      render(<ListState states={states}>{defaultChildren}</ListState>);

      // Assert
      expect(screen.getByText("Произошла ошибка")).toBeInTheDocument();
      expect(screen.getByText(errorMessage)).toBeInTheDocument();
      expect(screen.getByTestId("mock-icon")).toHaveAttribute(
        "data-name",
        "cloudWarning",
      );
      expect(screen.queryByTestId("children-content")).not.toBeInTheDocument();
    });

    /**
     * @description Should not render error UI when error is not a string (null, undefined, object)
     * @scenario Set states: { error: null } or { error: { message: "fail" } }
     * @expected Children are rendered, no error UI appears
     */
    it("should render children when error is null", () => {
      // Arrange
      const states = { error: null, itemsCount: 1 };

      // Act
      render(<ListState states={states}>{defaultChildren}</ListState>);

      // Assert
      expect(screen.getByTestId("children-content")).toBeInTheDocument();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });

    it("should render children when error is an object (non-string)", () => {
      // Arrange
      const states = { error: { message: "fail" }, itemsCount: 1 };

      // Act
      render(<ListState states={states}>{defaultChildren}</ListState>);

      // Assert
      expect(screen.getByTestId("children-content")).toBeInTheDocument();
    });

    /**
     * @description Should render custom error UI when renderError is provided
     * @scenario Pass renders.renderError that returns custom content
     * @expected Custom error content displayed, default UI not present
     */
    it("should render custom error UI when renderError is provided", () => {
      // Arrange
      const errorMsg = "API error";
      const states = { error: errorMsg };
      const renders: IListStatesRenders = {
        renderError: (err: string) => (
          <div data-testid="custom-error">Error: {err}</div>
        ),
      };

      // Act
      render(
        <ListState states={states} renders={renders}>
          {defaultChildren}
        </ListState>,
      );

      // Assert
      expect(screen.getByTestId("custom-error")).toHaveTextContent(
        `Error: ${errorMsg}`,
      );
      expect(screen.queryByText("Произошла ошибка")).not.toBeInTheDocument();
    });
  });

  // ===========================================================================

  describe("when empty state is active (itemsCount === 0)", () => {
    /**
     * @description Should render default empty UI with no text when emptyMessage is not provided (current implementation bug: fallback message not shown)
     * @scenario Set states: { itemsCount: 0, emptyMessage: undefined }
     * @expected Icon and empty <p> tag are displayed, no fallback text appears
     */
    it("should render default empty UI with empty paragraph when emptyMessage is not provided", () => {
      // Arrange
      const states = { itemsCount: 0 };

      // Act
      render(<ListState states={states}>{defaultChildren}</ListState>);

      // Assert
      const paragraph = document.querySelector(".list-state__default-block p");
      expect(paragraph).toBeInTheDocument();
      expect(paragraph).toHaveTextContent("");
      expect(screen.getByTestId("mock-icon")).toHaveAttribute(
        "data-name",
        "cloudBad",
      );
      expect(screen.queryByText("Ничего не найдено")).not.toBeInTheDocument();
      expect(screen.queryByTestId("children-content")).not.toBeInTheDocument();
    });

    /**
     * @description Should render empty UI with custom emptyMessage when provided
     * @scenario Set states: { itemsCount: 0, emptyMessage: "No files uploaded" }
     * @expected Custom message is shown
     */
    it("should render empty UI with custom emptyMessage when provided", () => {
      // Arrange
      const customMessage = "No files uploaded";
      const states = { itemsCount: 0, emptyMessage: customMessage };

      // Act
      render(<ListState states={states}>{defaultChildren}</ListState>);

      // Assert
      expect(screen.getByText(customMessage)).toBeInTheDocument();
      expect(screen.queryByTestId("children-content")).not.toBeInTheDocument();
    });

    /**
     * @description Should return null (render nothing) when hideEmptyState is true and itemsCount === 0
     * @scenario Set states: { itemsCount: 0, hideEmptyState: true }
     * @expected No empty UI and no children are rendered, container is empty
     */
    it("should render null when hideEmptyState is true and itemsCount === 0", () => {
      // Arrange
      const states = { itemsCount: 0, hideEmptyState: true };

      // Act
      const { container } = render(
        <ListState states={states}>{defaultChildren}</ListState>,
      );

      // Assert
      expect(container.firstChild).toBeNull();
      expect(screen.queryByTestId("children-content")).not.toBeInTheDocument();
    });

    /**
     * @description Should render custom empty UI when renderEmpty is provided
     * @scenario Pass renders.renderEmpty returning custom node
     * @expected Custom empty content displayed, default UI not present
     */
    it("should render custom empty UI when renderEmpty is provided", () => {
      // Arrange
      const states = { itemsCount: 0, emptyMessage: "Custom empty msg" };
      const renders: IListStatesRenders = {
        renderEmpty: (msg: string) => (
          <div data-testid="custom-empty">💡 {msg}</div>
        ),
      };

      // Act
      render(
        <ListState states={states} renders={renders}>
          {defaultChildren}
        </ListState>,
      );

      // Assert
      expect(screen.getByTestId("custom-empty")).toHaveTextContent(
        "💡 Custom empty msg",
      );
      expect(screen.queryByTestId("mock-icon")).not.toBeInTheDocument();
    });
  });

  // ===========================================================================

  describe("priority of states", () => {
    /**
     * @description Should prioritize loading over error and empty when isLoading true
     * @scenario Set states: { isLoading: true, error: "some error", itemsCount: 0 }
     * @expected Loading UI is displayed, not error or empty
     */
    it("should show loading UI when isLoading true despite error and empty conditions", () => {
      // Arrange
      const states = {
        isLoading: true,
        error: "Something went wrong",
        itemsCount: 0,
      };

      // Act
      render(<ListState states={states}>{defaultChildren}</ListState>);

      // Assert
      expect(screen.getByText("Загрузка...")).toBeInTheDocument();
      expect(screen.queryByText("Произошла ошибка")).not.toBeInTheDocument();
      expect(screen.queryByText("Ничего не найдено")).not.toBeInTheDocument();
    });

    /**
     * @description Should show error UI when error is string and loading false, regardless of itemsCount
     * @scenario Set states: { isLoading: false, error: "fail", itemsCount: 0 }
     * @expected Error UI is displayed, not empty or children
     */
    it("should show error UI when error is string even if itemsCount === 0", () => {
      // Arrange
      const states = {
        isLoading: false,
        error: "Data fetch error",
        itemsCount: 0,
      };

      // Act
      render(<ListState states={states}>{defaultChildren}</ListState>);

      // Assert
      expect(screen.getByText("Произошла ошибка")).toBeInTheDocument();
      expect(screen.queryByText("Ничего не найдено")).not.toBeInTheDocument();
    });

    /**
     * @description Should show empty UI when itemsCount === 0, loading false, and error null/undefined
     * @scenario Set states: { isLoading: false, error: null, itemsCount: 0 }
     * @expected Empty UI displayed (without fallback text due to current bug)
     */
    it("should show empty UI when itemsCount === 0 and no loading/error", () => {
      // Arrange
      const states = {
        isLoading: false,
        error: null,
        itemsCount: 0,
      };

      // Act
      render(<ListState states={states}>{defaultChildren}</ListState>);

      // Assert
      const paragraph = document.querySelector(".list-state__default-block p");
      expect(paragraph).toBeInTheDocument();
      expect(paragraph).toHaveTextContent("");
      expect(screen.getByTestId("mock-icon")).toHaveAttribute(
        "data-name",
        "cloudBad",
      );
      expect(screen.queryByText("Ничего не найдено")).not.toBeInTheDocument();
    });
  });
});
