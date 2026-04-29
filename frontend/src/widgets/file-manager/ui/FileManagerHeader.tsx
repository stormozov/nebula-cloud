import type React from "react";

import { FileSearchInput } from "@/features/file/file-search";
import { FileUploadButton } from "@/features/file/file-upload";
import { HelpKeyboardShortcutsButton } from "@/features/help";
import { useMediaQuery } from "@/shared/hooks";
import {
  BackButton,
  Badge,
  ControlledInput,
  Heading,
  PageWrapper,
} from "@/shared/ui";

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
  const isMobile600px = useMediaQuery({ query: "(max-width: 600px)" });
  const isMobile440px = useMediaQuery({ query: "(max-width: 440px)" });
  const isMobile375px = useMediaQuery({ query: "(max-width: 375px)" });

  if (!isAdmin) {
    return (
      <header className="file-manager__header file-manager__header--user-mode">
        <PageWrapper
          align="center"
          justify="space-between"
          className="file-manager__header-top"
        >
          <Heading level={2} noMargin className="file-manager__header-title">
            Ваш диск
          </Heading>
          <PageWrapper align="center">
            {!isMobile600px && (
              <FileSearchInput
                inputProps={{
                  value: searchTerm,
                  placeholder: "Поиск по названию и дате загрузки",
                  onChange: onSearchChange,
                }}
              />
            )}
            <HelpKeyboardShortcutsButton
              buttonProps={{ variant: "secondary" }}
            />
            <FileUploadButton>
              {isMobile440px ? "" : "Загрузить файл"}
            </FileUploadButton>
          </PageWrapper>
        </PageWrapper>

        {storageWidget}

        {isMobile600px && (
          <ControlledInput
            value={searchTerm}
            className="file-manager__mobile-search"
            placeholder={"Поиск по ID, логину или email"}
            autoComplete="off"
            onChange={onSearchChange}
          />
        )}
      </header>
    );
  }

  return (
    <header className="file-manager__header file-manager__header--admin-mode">
      <PageWrapper
        direction={isMobile600px ? "column" : "row"}
        align="center"
        justify="space-between"
        className="file-manager__header-top"
      >
        <PageWrapper
          direction={isMobile375px ? "column" : "row"}
          align={isMobile375px ? "center" : "start"}
        >
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
              size: !isMobile600px ? "small" : "medium",
            }}
            inputProps={{
              value: searchTerm,
              placeholder: "Поиск по названию и дате загрузки",
              onChange: onSearchChange,
            }}
          />
          <HelpKeyboardShortcutsButton
            buttonProps={{
              variant: "secondary",
              size: !isMobile600px ? "small" : "medium",
            }}
          />
        </PageWrapper>
      </PageWrapper>
      {storageWidget}
    </header>
  );
}
