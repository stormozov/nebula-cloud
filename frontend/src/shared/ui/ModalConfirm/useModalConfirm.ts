import { useCallback, useState } from "react";

import type { IModalConfirmState, IUseModalConfirmReturns } from "./types";

/**
 * Custom React Hook for managing a confirmation modal dialog.
 *
 * Provides state and actions to control the visibility and behavior of a modal
 * that prompts the user for confirmation before performing a critical action.
 *
 * @returns An object containing the current dialog state and control functions.
 *
 * @example
 * const { dialog, requestConfirm, handleConfirm, handleCancel } = useModalConfirm();
 *
 * return (
 *   <>
 *     <button onClick={() => requestConfirm("Delete item", "Are you sure?", handleDelete)}>
 *       Delete
 *     </button>
 *     <ModalConfirm
 *       isOpen={dialog.isOpen}
 *       title={dialog.title}
 *       message={dialog.message}
 *       onConfirm={handleConfirm}
 *       onCancel={handleCancel}
 *     />
 *   </>
 * );
 */
export const useModalConfirm = (): IUseModalConfirmReturns => {
  const [dialog, setDialog] = useState<IModalConfirmState>({
    isOpen: false,
    title: "",
    message: "",
    onConfirm: async () => {},
  });

  const requestConfirm = useCallback(
    (title: string, message: string, onConfirm: () => Promise<void>) => {
      setDialog({ isOpen: true, title, message, onConfirm });
    },
    [],
  );

  const handleConfirm = useCallback(async () => {
    await dialog.onConfirm();
    setDialog((prev) => ({ ...prev, isOpen: false }));
  }, [dialog]);

  const handleCancel = useCallback(() => {
    setDialog((prev) => ({ ...prev, isOpen: false }));
  }, []);

  return {
    dialog,
    requestConfirm,
    handleConfirm,
    handleCancel,
  };
};
