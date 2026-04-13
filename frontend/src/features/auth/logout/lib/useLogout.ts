import { useCallback } from "react";
import { useNavigate } from "react-router";
import { toast } from "react-toastify";

import { useLogoutMutation } from "@/entities/user";

/**
 * Interface describing the return value of the `useLogout` hook.
 */
interface IUseLogoutReturns {
  /** Indicates whether the logout request is currently being processed. */
  isLoading: boolean;
  /** Asynchronous function that performs the logout operation. */
  logout: () => Promise<void>;
}

/**
 * Custom hook that handles user logout logic.
 *
 * @example
 * const { logout, isLoading } = useLogout();
 * <button onClick={logout} disabled={isLoading}>
 *   {isLoading ? 'Выход...' : 'Выйти'}
 * </button>
 */
export const useLogout = (): IUseLogoutReturns => {
  const navigate = useNavigate();
  const [logoutMutation, { isLoading }] = useLogoutMutation();

  const logout = useCallback(async () => {
    try {
      await logoutMutation().unwrap();
      toast.info("Вы вышли из аккаунта", {
        position: "bottom-center",
        autoClose: 2000,
        theme: "light",
      });
      navigate("/", { replace: true });
    } catch {
      navigate("/", { replace: true });
    }
  }, [logoutMutation, navigate]);

  return { isLoading, logout };
};
