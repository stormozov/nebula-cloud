import { configureStore } from "@reduxjs/toolkit";
import { type RenderOptions, render } from "@testing-library/react";
import type { ReactElement } from "react";
import { Provider } from "react-redux";
import { MemoryRouter } from "react-router";

import { userApi, userReducer } from "../../src/entities/user";

/**
 * Creates a test store with minimal configuration.
 */
export const createTestStore = () =>
  configureStore({
    reducer: {
      user: userReducer,
      [userApi.reducerPath]: userApi.reducer,
    },
    middleware: (getDefault) => getDefault().concat(userApi.middleware),
  });

/**
 * Custom render wrapper with providers (Redux, Router).
 */
interface ICustomRenderOptions extends Omit<RenderOptions, "wrapper"> {
  store?: ReturnType<typeof createTestStore>;
  initialEntries?: string[];
}

export const renderWithProviders = (
  ui: ReactElement,
  {
    store = createTestStore(),
    initialEntries = ["/"],
    ...renderOptions
  }: ICustomRenderOptions = {},
) => {
  const Wrapper = ({ children }: { children: React.ReactNode }) => (
    <Provider store={store}>
      <MemoryRouter initialEntries={initialEntries}>{children}</MemoryRouter>
    </Provider>
  );

  return {
    store,
    ...render(ui, { wrapper: Wrapper, ...renderOptions }),
  };
};
