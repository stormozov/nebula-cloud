import type React from "react";

import { FileSearchInput } from "@/features/file/file-search";
import { FileUploadButton } from "@/features/file/file-upload";
import { HelpKeyboardShortcutsButton } from "@/features/help";
import { BackButton, Badge, Heading, PageWrapper } from "@/shared/ui";

/**
 * Props for the FileManagerHeader component.
 */
interface FileManagerHeaderProps {
  /**
   * Indicates whether the current user has admin privileges.
   */
  isAdmin: boolean;
  /**
   * Optional user ID to display in the header when viewing another user's files.
   */
  userId?: number;
  /** Optional storage widget to display in the header. */
  storageWidget?: React.ReactNode;
  /** Current search term entered by the user. */
  searchTerm: string;
  /**
   * Callback function triggered when the search term changes.
   *
   * @param value - The updated search string entered by the user.
   */
  onSearchChange: (value: string) => void;
}

/**
 * Header component for the file manager that displays different UI based
 * on user role.
 */
export function FileManagerHeader({
  isAdmin,
  userId,
  searchTerm,
  storageWidget,
  onSearchChange,
}: FileManagerHeaderProps) {
  if (!isAdmin) {
    return (
      <header className="file-manager__header">
        <PageWrapper
          align="center"
          justify="space-between"
          className="file-manager__header-top"
        >
          <Heading level={2} noMargin className="file-manager__header-title">
            Ваш диск
          </Heading>
          <PageWrapper align="center">
            <FileSearchInput
              inputProps={{
                value: searchTerm,
                placeholder: "Поиск по названию и дате загрузки",
                onChange: onSearchChange,
              }}
            />
            <HelpKeyboardShortcutsButton
              buttonProps={{ variant: "secondary" }}
            />
            <FileUploadButton>Загрузить файл</FileUploadButton>
          </PageWrapper>
        </PageWrapper>
        {storageWidget}
      </header>
    );
  }

  return (
    <header className="file-manager__header">
      <PageWrapper
        align="center"
        justify="space-between"
        className="file-manager__header-top"
      >
        <PageWrapper>
          <BackButton />
          <Heading level={2} noMargin className="file-manager__header-title">
            Файлы пользователя{" "}
            <Badge variant="info-light" icon="person" superscript copyable>
              {userId}
            </Badge>
          </Heading>
        </PageWrapper>
        <PageWrapper align="center">
          <FileSearchInput
            buttonProps={{
              children: "Поиск",
              size: "small",
            }}
            inputProps={{
              value: searchTerm,
              placeholder: "Поиск по названию и дате загрузки",
              onChange: onSearchChange,
            }}
          />
          <HelpKeyboardShortcutsButton
            buttonProps={{ variant: "secondary", size: "small" }}
          />
        </PageWrapper>
      </PageWrapper>
      {storageWidget}
    </header>
  );
}
