import {
  CollapsibleSearch,
  type ICollapsibleSearchProps,
} from "@/shared/ui/CollapsibleSearch";

/**
 * Type alias for the props of the `FileSearchInput` component.
 *
 * Inherits all properties from `ICollapsibleSearchProps` to ensure consistent
 * configuration with the underlying `CollapsibleSearch` component.
 */
type FileSearchInputProps = ICollapsibleSearchProps;

/**
 * A specialized wrapper around `CollapsibleSearch` tailored for file search
 * functionality.
 *
 * @example
 * <FileSearchInput
 *   inputProps={{
 *     value: fileName,
 *     onChange: handleFileNameChange,
 *     placeholder: "Search files..."
 *   }}
 * />
 */
export const FileSearchInput = (props: FileSearchInputProps) => {
  return <CollapsibleSearch {...props} />;
};
