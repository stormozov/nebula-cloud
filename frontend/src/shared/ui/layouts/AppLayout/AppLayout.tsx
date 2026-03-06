import { Outlet } from "react-router";

import { AppHeader } from "./AppHeader";
import { AppSidebar } from "./AppSidebar";

import "./AppLayout.scss";

/**
 * App layout component.
 */
export default function AppLayout() {
  return (
    <div className="app-layout">
      <AppHeader />
      <div className="app-content-wrap">
        <AppSidebar />
        <main className="app-main">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
