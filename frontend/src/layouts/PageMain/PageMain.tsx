import { Outlet } from "react-router";

import "./PageMain.scss";

/**
 * Main content layout component.
 */
export default function PageMain() {
  return (
    <main className="page-main">
      <div className="container">
        <Outlet />
      </div>
    </main>
  );
}
