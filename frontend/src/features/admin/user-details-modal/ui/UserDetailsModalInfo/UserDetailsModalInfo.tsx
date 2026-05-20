import classNames from "classnames";

import type { IStorageStatsResponse, IUser } from "@/entities/user";
import { Button, CopyIcon, Heading } from "@/shared/ui";

import type { IUserDetailsInfoItem } from "../../lib/types";
import { useBlockHover } from "../../lib/useBlockHover";
import { useClipboardWithHandlers } from "../../lib/useClipboardWithHandlers";
import { useUserBlocksData } from "../../lib/useUserBlocksData";
import { UserCopyableInfoRow } from "../UserCopyableInfoRow/UserCopyableInfoRow";

import "./UserDetailsModalInfo.scss";

/**
 * Props interface for the UserDetailsModalInfo component.
 */
interface IUserDetailsModalInfoProps {
  /** User data to be displayed in the modal. */
  user: IUser;
  /** Storage stats data to be displayed in the modal. */
  storageStats?: IStorageStatsResponse;
}

/**
 * Modal component for displaying detailed user info in structured blocks.
 *
 * Renders user data grouped into sections. Each section is interactive
 * — supports hover states and copying values via clipboard hooks.
 */
export function UserDetailsModalInfo({
  user,
  storageStats,
}: IUserDetailsModalInfoProps) {
  const blocks = useUserBlocksData(user, storageStats);
  const { handleRowClick, handleCopyBlock } = useClipboardWithHandlers();
  const { isHovered, handleMouseEnter, handleMouseLeave } = useBlockHover();

  // An auxiliary function for rendering a block
  const renderSection = (title: string, items: IUserDetailsInfoItem[]) => {
    const copyValues = items.map((item) => item.copyValue);

    return (
      <section
        key={title}
        className="user-details-modal-info__section"
        aria-label={`Блок информации о пользователе: ${title}`}
        onMouseEnter={() => handleMouseEnter(title)}
        onMouseLeave={handleMouseLeave}
      >
        <header
          className={classNames("user-details-modal-info__header", {
            hovered: isHovered(title),
          })}
        >
          <Heading
            level={4}
            visualSize="sm"
            noMargin
            className="user-details-modal-info__title"
          >
            {title}
          </Heading>
          <Button
            variant="text"
            className="user-details-modal-info__copy-block-btn"
            aria-label={`Скопировать все поля блока "${title}"`}
            onClick={() => handleCopyBlock(title, copyValues)}
          >
            <CopyIcon />
          </Button>
        </header>
        <div className="user-details-modal-info__items">
          {items.map((info) => (
            <div key={info.title} className="user-details-modal-info__item">
              {info.copyValue ? (
                <UserCopyableInfoRow
                  label={info.title}
                  value={info.value}
                  originalValue={info.originalValue}
                  copyValue={info.copyValue}
                  onCopy={handleRowClick}
                />
              ) : (
                info.value
              )}
            </div>
          ))}
        </div>
      </section>
    );
  };

  return (
    <aside className="user-details-modal-info">
      {blocks.map(({ title, items }) => renderSection(title, items))}
    </aside>
  );
}
