import { memo } from "react";

import "./ListSkeleton.scss";
import { generateSkeletonKeys } from "./utils";

/**
 * Props interface for the ListSkeleton component.
 */
export interface ListSkeletonProps {
  /** Number of columns to render in the skeleton table. */
  columnCount?: number;
  /** Number of rows to render in the skeleton table. */
  rowCount?: number;
  /** Optional CSS class name(s) to apply to the root element. */
  className?: string;
}

/**
 * A memoized skeleton loader component that displays a table-like structure
 * with animated placeholders.
 *
 * @example
 * <ListSkeleton columnCount={4} rowCount={8} className="custom-class" />
 */
export const ListSkeleton = memo(function ListSkeleton({
  columnCount = 5,
  rowCount = 6,
  className = "",
}: ListSkeletonProps) {
  const { headerKeys, gridRows } = generateSkeletonKeys(columnCount, rowCount);

  return (
    // biome-ignore lint/a11y/useSemanticElements: <role status needs for screen readers>
    <div
      className={`users-list ${className}`.trim()}
      role="status"
      aria-busy="true"
      aria-label="Загрузка данных таблицы"
    >
      <table className="users-list__table">
        <thead className="users-list__header">
          <tr className="users-list__header-row">
            {headerKeys.map((key) => (
              <th key={key} className="users-list__header-cell">
                <div className="users-list-cell-skeleton" aria-hidden="true" />
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="users-list__body">
          {gridRows.map(({ rowKey, cellKeys }) => (
            <tr key={rowKey} className="users-list__body-row">
              {cellKeys.map((key) => (
                <td key={key} className="users-list__body-cell">
                  <div
                    className="users-list-cell-skeleton"
                    aria-hidden="true"
                  />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
});
