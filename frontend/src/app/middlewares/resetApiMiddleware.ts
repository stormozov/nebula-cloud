import type { Middleware } from "@reduxjs/toolkit";

import { fileApi } from "@/entities/file";
import { userApi, userSlice } from "@/entities/user";

/**
 * Reset API state on logout
 */
export const resetApiMiddleware: Middleware = (store) => (next) => (action) => {
  const result = next(action);

  if (userSlice.actions.logout.match(action)) {
    store.dispatch(userApi.util.resetApiState());
    store.dispatch(fileApi.util.resetApiState());
  }

  return result;
};
