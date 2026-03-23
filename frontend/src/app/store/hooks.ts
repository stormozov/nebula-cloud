import {
  type TypedUseSelectorHook,
  useDispatch,
  useSelector,
} from "react-redux";

import type { AppDispatch, RootState } from "./store";

/**
 * Typed dispatch hook for use throughout the app.
 * Provides full type inference for dispatch actions.
 *
 * @example
 * const dispatch = useAppDispatch();
 * dispatch(addFiles({ files })); // Full type inference
 */
export const useAppDispatch = () => useDispatch<AppDispatch>();

/**
 * Typed selector hook for use throughout the app.
 * Provides full type inference for state selectors.
 *
 * @example
 * const files = useAppSelector(selectFileList);
 */
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector;
