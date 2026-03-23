import type { IFileListHeaderProps } from "../lib/types";

import "./FileList.scss";

/**
 * A presentational component that renders the header row of a file list table.
 *
 * @example
 * <FileListHeader
 *   columns={[
 *     { key: 'name', label: 'File Name', className: 'col-name' },
 *     { key: 'size', label: 'Size' },
 *     { key: 'modified', label: 'Modified', className: 'col-date' },
 *   ]}
 * />
 */
export const FileListHeader = ({ columns }: IFileListHeaderProps) => {
  return (
    <thead className="file-list__header">
      <tr>
        {columns.map((column) => (
          <th
            key={column.key}
            className={`file-list__header-cell ${column.className || ""}`}
            scope="col"
          >
            {column.label}
          </th>
        ))}
      </tr>
    </thead>
  );
};
