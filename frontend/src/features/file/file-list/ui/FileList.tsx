import { ListState } from "@/shared/ui/ListState";

import type { IFileListProps } from "../lib/types";
import { useFileListKeyboardShortcuts } from "../lib/useFileListKeyboardShortcuts";
import { FileListBody } from "./FileListBody";
import { FileListHeader } from "./FileListHeader";

import "./FileList.scss";

/**
 * A component that renders a list of files in a tabular format with support
 * for loading, error, and empty states.
 */
export function FileList({
  files,
  states = {},
  handlers = {},
  renders = {},
  headers = [],
  onSelectFile,
}: IFileListProps) {
  useFileListKeyboardShortcuts({ files, handlers });

  return (
    <ListState
      states={{ ...states, itemsCount: files.length }}
      renders={renders}
    >
      <div className="file-list">
        <table className="file-list__table">
          <FileListHeader columns={headers} />
          <FileListBody
            files={files}
            onSelect={onSelectFile}
            handlers={handlers}
          />
        </table>
      </div>
    </ListState>
  );
}
