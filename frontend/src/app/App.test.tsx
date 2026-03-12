import type { RenderResult } from "@testing-library/react";
import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { routesConfig } from "@/app/routes";

import App from "./App";
import { store } from "./store/store";

describe("App", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("renders successfully", () => {
    /**
     * @description Renders successfully
     * @scenario App component mounts without errors
     * @expected renders without crashing
     */
    it("should render without crashing", () => {
      expect(() => render(<App />)).not.toThrow();
    });
  });

  describe("uses correct Redux store", () => {
    /**
     * @description Uses correct Redux store
     * @scenario App imports and uses the application store
     * @expected store is defined, with getState and dispatch methods
     */
    it("should import the correct store", () => {
      expect(store).toBeDefined();
      expect(store.getState).toBeDefined();
      expect(store.dispatch).toBeDefined();
    });
  });

  describe("uses correct router configuration", () => {
    /**
     * @description Uses correct router configuration
     * @scenario App imports and uses routesConfig
     * @expected routesConfig is defined and of type object
     */
    it("should import the correct routesConfig", () => {
      expect(routesConfig).toBeDefined();
      expect(routesConfig).toHaveProperty("basename");
      expect(typeof routesConfig).toBe("object");
    });
  });

  /**
   * @description Should match snapshot
   * @scenario Snapshot test to verify overall component structure
   * @expected App component renders correctly
   */
  it("should match snapshot", () => {
    const result: RenderResult = render(<App />);
    expect(result.container).toMatchSnapshot();
  });
});
