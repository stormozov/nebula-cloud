/**
 * Array of objects, each representing a row in the grid.
 */
interface IGridRowsReturns {
  /** Unique key for the grid row. */
  rowKey: string;
  /** Array of unique keys for skeleton cells within the row. */
  cellKeys: string[];
}

/**
 * Interface representing the return value of the generateSkeletonKeys function.
 */
interface IGenerateSkeletonKeysReturns {
  /** Array of unique keys for skeleton header cells. */
  headerKeys: string[];
  /** Array of objects, each representing a row in the grid. */
  gridRows: IGridRowsReturns[];
}

/**
 * Generates unique keys for skeleton UI elements in a grid or table layout.
 *
 * Used to create stable keys for rendering loading skeletons in a tabular
 * format, ensuring consistent rendering and avoiding key duplication.
 *
 * @param {number} columnCount - The number of columns in the grid.
 * @param {number} rowCount - The number of rows in the grid.
 *
 * @example
 * const keys = generateSkeletonKeys(3, 2);
 * // Returns:
 * // {
 * //   headerKeys: ['header-0', 'header-1', 'header-2'],
 * //   gridRows: [
 * //     { rowKey: 'row-0', cellKeys: ['row-0-col-0', 'row-0-col-1', 'row-0-col-2'] },
 * //     { rowKey: 'row-1', cellKeys: ['row-1-col-0', 'row-1-col-1', 'row-1-col-2'] }
 * //   ]
 * // }
 */
export const generateSkeletonKeys = (
  columnCount: number,
  rowCount: number,
): IGenerateSkeletonKeysReturns => {
  const headerKeys = Array.from(
    { length: columnCount },
    (_, i) => `header-${i}`,
  );

  const gridRows = Array.from({ length: rowCount }, (_, r) => ({
    rowKey: `row-${r}`,
    cellKeys: Array.from(
      { length: columnCount },
      (_, c) => `row-${r}-col-${c}`,
    ),
  }));

  return { headerKeys, gridRows };
};
