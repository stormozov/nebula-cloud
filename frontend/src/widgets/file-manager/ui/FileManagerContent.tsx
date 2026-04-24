import { FileList, type IFileListProps } from "@/features/file/file-list";
import { Button } from "@/shared/ui";

/**
 * Props for the `FileManagerContent` component.
 */
interface FileManagerContentProps {
  /** Indicates whether there are more pages of files to load. */
  hasNextPage: boolean;
  /** Indicates whether data is currently being fetched from the server. */
  isFetching: boolean;
  /** Props object passed directly to the FileList component. */
  fileListProps: IFileListProps;
  /** Callback function to load the next page of files. */
  loadMore: () => void;
}

/**
 * Main content area of the file manager that displays the list of files
 * and a "Load More" button when additional pages are available.
 */
export const FileManagerContent = ({
  hasNextPage,
  isFetching,
  fileListProps,
  loadMore,
}: FileManagerContentProps) => {
  return (
    <div className="file-manager__list">
      <FileList {...fileListProps} />
      {hasNextPage && (
        <div className="file-manager__load-more">
          <Button
            icon={{ name: "retry" }}
            loading={isFetching}
            disabled={isFetching}
            onClick={loadMore}
          >
            Загрузить ещё
          </Button>
        </div>
      )}
    </div>
  );
};
