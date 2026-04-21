import { useState } from "react";

import { CopyIcon } from "@/shared/ui";

import "./UserCopyableInfoRow.scss";

/**
 * Props for the `CopyableInfoRow` component.
 */
interface ICopyableInfoRowProps {
  label: string;
  value: React.ReactNode;
  originalValue?: string;
  copyValue: string;
  onCopy: (copyValue: string, title: string) => void;
}

/**
 * A reusable UI component representing a row of user information that can be
 * copied to the clipboard.
 *
 * Displays a label and value in a button-like row. When clicked, copies
 * the specified value and shows a visual feedback (via CopyIcon) indicating
 * success for one second.
 */
export function UserCopyableInfoRow({
  label,
  value,
  originalValue,
  copyValue,
  onCopy,
}: ICopyableInfoRowProps) {
  const [copied, setCopied] = useState(false);

  const handleClick = () => {
    onCopy(copyValue, label);
    setCopied(true);
    setTimeout(() => setCopied(false), 1000);
  };

  return (
    <button
      type="button"
      className="user-details-modal-info-copyable-row w-full"
      title={originalValue}
      aria-label={`Скопировать ${label}`}
      onClick={handleClick}
    >
      <p className="user-details-modal-info__label">{label}:</p>
      <span className="user-details-modal-info__value">{value}</span>
      <CopyIcon
        iconProps={{
          name: copied ? "check" : "copy",
          color: "text-tertiary",
          className: "user-details-modal-info__copy-decor-icon",
        }}
      />
    </button>
  );
}
