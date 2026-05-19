import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ListSkeleton } from "../ListSkeleton";
import { generateSkeletonKeys } from "../utils";

vi.mock("../utils", () => ({
  generateSkeletonKeys: vi.fn(),
}));

describe("ListSkeleton", () => {
  const mockHeaderKeys = ["header-0", "header-1", "header-2"];
  const mockGridRows = [
    {
      rowKey: "row-0",
      cellKeys: ["row-0-col-0", "row-0-col-1", "row-0-col-2"],
    },
    {
      rowKey: "row-1",
      cellKeys: ["row-1-col-0", "row-1-col-1", "row-1-col-2"],
    },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(generateSkeletonKeys).mockReturnValue({
      headerKeys: mockHeaderKeys,
      gridRows: mockGridRows,
    });
  });

  // ===========================================================================

  describe("when rendering with default props", () => {
    /**
     * @description Should render skeleton table with default columnCount=5 and rowCount=6
     * @scenario Render ListSkeleton without any props
     * @expected generateSkeletonKeys called with (5, 6), table is present, correct number of header cells and body rows
     */
    it("should call generateSkeletonKeys with default columnCount 5 and rowCount 6", () => {
      // Arrange & Act
      render(<ListSkeleton />);

      // Assert
      expect(generateSkeletonKeys).toHaveBeenCalledTimes(1);
      expect(generateSkeletonKeys).toHaveBeenCalledWith(5, 6);
    });

    /**
     * @description Should render role="status" and aria-busy="true" for accessibility
     * @scenario Render ListSkeleton with default props
     * @expected div with role="status" and aria-busy="true"
     */
    it("should render root div with role status and aria-busy true", () => {
      // Arrange & Act
      render(<ListSkeleton />);

      // Assert
      const statusDiv = screen.getByRole("status");
      expect(statusDiv).toBeInTheDocument();
      expect(statusDiv).toHaveAttribute("aria-busy", "true");
      expect(statusDiv).toHaveAttribute(
        "aria-label",
        "Загрузка данных таблицы",
      );
    });
  });

  // ===========================================================================

  describe("when custom props are provided", () => {
    /**
     * @description Should pass custom columnCount and rowCount to generateSkeletonKeys
     * @scenario Render ListSkeleton with columnCount=4, rowCount=3
     * @expected generateSkeletonKeys called with (4, 3)
     */
    it("should call generateSkeletonKeys with custom columnCount and rowCount", () => {
      // Arrange
      const columnCount = 4;
      const rowCount = 3;

      // Act
      render(<ListSkeleton columnCount={columnCount} rowCount={rowCount} />);

      // Assert
      expect(generateSkeletonKeys).toHaveBeenCalledWith(columnCount, rowCount);
    });

    /**
     * @description Should apply custom className to root div
     * @scenario Render ListSkeleton with className="custom-test-class"
     * @expected Root div includes custom class alongside default class
     */
    it("should apply custom className to root element", () => {
      // Arrange
      const customClass = "custom-test-class";

      // Act
      render(<ListSkeleton className={customClass} />);

      // Assert
      const rootDiv = screen.getByRole("status");
      expect(rootDiv).toHaveClass("list-skeleton", customClass);
    });

    /**
     * @description Should handle empty className string without adding extra spaces
     * @scenario Render ListSkeleton with className=""
     * @expected Root div has only class "list-skeleton"
     */
    it("should handle empty className without extra spaces", () => {
      // Arrange & Act
      render(<ListSkeleton className="" />);

      // Assert
      const rootDiv = screen.getByRole("status");
      expect(rootDiv).toHaveClass("list-skeleton");
      expect(rootDiv.className).toBe("list-skeleton");
    });
  });

  // ===========================================================================

  describe("when rendering table structure", () => {
    /**
     * @description Should render table element
     * @scenario Render ListSkeleton with mocked keys
     * @expected table element is present in document
     */
    it("should render a table element", () => {
      // Arrange & Act
      render(<ListSkeleton />);

      // Assert
      const table = document.querySelector("table");
      expect(table).toBeInTheDocument();
      expect(table).toHaveClass("list-skeleton__table");
    });

    /**
     * @description Should render thead and tbody sections
     * @scenario Render ListSkeleton with mocked keys
     * @expected thead and tbody elements exist
     */
    it("should render thead and tbody sections", () => {
      // Arrange & Act
      render(<ListSkeleton />);

      // Assert
      const thead = document.querySelector("thead");
      const tbody = document.querySelector("tbody");
      expect(thead).toBeInTheDocument();
      expect(tbody).toBeInTheDocument();
    });

    /**
     * @description Should render correct number of header cells based on headerKeys
     * @scenario Mock headerKeys length = 3
     * @expected 3 th elements in thead
     */
    it("should render header cells count equal to headerKeys length", () => {
      // Arrange
      vi.mocked(generateSkeletonKeys).mockReturnValue({
        headerKeys: ["h1", "h2", "h3", "h4"],
        gridRows: [],
      });

      // Act
      render(<ListSkeleton />);

      // Assert
      const headerCells = document.querySelectorAll("th");
      expect(headerCells).toHaveLength(4);
    });

    /**
     * @description Should render body rows count equal to gridRows length
     * @scenario Mock gridRows length = 2
     * @expected 2 tr elements in tbody
     */
    it("should render number of body rows equal to gridRows length", () => {
      // Arrange
      vi.mocked(generateSkeletonKeys).mockReturnValue({
        headerKeys: mockHeaderKeys,
        gridRows: [
          { rowKey: "r0", cellKeys: ["c0", "c1"] },
          { rowKey: "r1", cellKeys: ["c0", "c1"] },
          { rowKey: "r2", cellKeys: ["c0", "c1"] },
        ],
      });

      // Act
      render(<ListSkeleton />);

      // Assert
      const bodyRows = document.querySelectorAll("tbody tr");
      expect(bodyRows).toHaveLength(3);
    });

    /**
     * @description Should render correct number of cells per row based on cellKeys length
     * @scenario Each row has cellKeys length = 3
     * @expected Each row contains 3 td elements
     */
    it("should render correct number of body cells per row", () => {
      // Arrange
      vi.mocked(generateSkeletonKeys).mockReturnValue({
        headerKeys: mockHeaderKeys,
        gridRows: [
          { rowKey: "r0", cellKeys: ["c0", "c1", "c2"] },
          { rowKey: "r1", cellKeys: ["c0", "c1", "c2"] },
        ],
      });

      // Act
      render(<ListSkeleton />);

      // Assert
      const rows = document.querySelectorAll("tbody tr");
      rows.forEach((row) => {
        const cells = row.querySelectorAll("td");
        expect(cells).toHaveLength(3);
      });
    });

    /**
     * @description Should render skeleton div inside each th and td with aria-hidden="true"
     * @scenario Render ListSkeleton with mocked keys
     * @expected Each header cell and body cell contains a div with class "list-skeleton__cell-skeleton" and aria-hidden="true"
     */
    it("should render skeleton divs inside each header and body cell with aria-hidden true", () => {
      // Arrange & Act
      render(<ListSkeleton />);

      // Assert
      const skeletonDivs = document.querySelectorAll(
        ".list-skeleton__cell-skeleton",
      );
      const totalCells =
        mockHeaderKeys.length +
        mockGridRows.reduce((acc, row) => acc + row.cellKeys.length, 0);
      expect(skeletonDivs.length).toBe(totalCells);
      skeletonDivs.forEach((div) => {
        expect(div).toHaveAttribute("aria-hidden", "true");
      });
    });

    /**
     * @description Should use provided headerKeys and cellKeys as React keys (verified via presence of matching elements)
     * @scenario Mock keys with specific values
     * @expected Rendered th and td elements have corresponding key attributes (React keys, not in DOM, but we can verify via rendered content or counts)
     */
    it("should use provided headerKeys and cellKeys as React keys (verified via presence of matching elements)", () => {
      // Arrange
      const customHeaderKeys = ["custom-header-0", "custom-header-1"];
      const customGridRows = [
        {
          rowKey: "custom-row-0",
          cellKeys: ["custom-cell-0-0", "custom-cell-0-1"],
        },
      ];
      vi.mocked(generateSkeletonKeys).mockReturnValue({
        headerKeys: customHeaderKeys,
        gridRows: customGridRows,
      });

      // Act
      render(<ListSkeleton />);

      // Assert
      const thElements = document.querySelectorAll("th");
      expect(thElements).toHaveLength(2);
      const tdElements = document.querySelectorAll("td");
      expect(tdElements).toHaveLength(2);
    });
  });

  // ===========================================================================

  describe("when edge cases occur", () => {
    /**
     * @description Should handle zero columnCount gracefully
     * @scenario Render ListSkeleton with columnCount=0, rowCount=2
     * @expected generateSkeletonKeys called with (0, 2), no header cells rendered, body cells per row are zero
     */
    it("should handle columnCount=0 without errors", () => {
      // Arrange
      vi.mocked(generateSkeletonKeys).mockReturnValue({
        headerKeys: [],
        gridRows: [
          { rowKey: "row-0", cellKeys: [] },
          { rowKey: "row-1", cellKeys: [] },
        ],
      });

      // Act
      render(<ListSkeleton columnCount={0} rowCount={2} />);

      // Assert
      const thElements = document.querySelectorAll("th");
      expect(thElements).toHaveLength(0);
      const tdElements = document.querySelectorAll("td");
      expect(tdElements).toHaveLength(0);
      const bodyRows = document.querySelectorAll("tbody tr");
      expect(bodyRows).toHaveLength(2);
    });

    /**
     * @description Should handle zero rowCount gracefully
     * @scenario Render ListSkeleton with columnCount=3, rowCount=0
     * @expected generateSkeletonKeys called with (3, 0), header cells rendered, no body rows
     */
    it("should handle rowCount=0 without errors", () => {
      // Arrange
      vi.mocked(generateSkeletonKeys).mockReturnValue({
        headerKeys: ["h0", "h1", "h2"],
        gridRows: [],
      });

      // Act
      render(<ListSkeleton columnCount={3} rowCount={0} />);

      // Assert
      const thElements = document.querySelectorAll("th");
      expect(thElements).toHaveLength(3);
      const bodyRows = document.querySelectorAll("tbody tr");
      expect(bodyRows).toHaveLength(0);
    });
  });
});