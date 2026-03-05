import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "./App";

import "./index.scss";

const root = document.getElementById("root");

createRoot(root ? root : document.body).render(
	<StrictMode>
		<App />
	</StrictMode>,
);
