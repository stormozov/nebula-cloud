import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "./app/App";
import { store } from "./app/store/store";
import { setTokens } from "./entities/user";

import "./index.scss";

const initAuthFromStorage = () => {
  const accessToken = localStorage.getItem("accessToken");
  const refreshToken = localStorage.getItem("refreshToken");

  if (accessToken && refreshToken) {
    store.dispatch(setTokens({ access: accessToken, refresh: refreshToken }));
  }
};

initAuthFromStorage();

const root = document.getElementById("root");

createRoot(root ? root : document.body).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
