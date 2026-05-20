import { beforeEach, describe, expect, it } from "vitest";

import type { COLOR_SCHEMES } from "@/shared/types/theme";

import { applyTheme } from "../applyTheme";

describe("applyTheme", () => {
  beforeEach(() => {
    document.documentElement.removeAttribute("data-theme");
    document.documentElement.style.colorScheme = "";
  });

  describe("when called with a color scheme", () => {
    const scheme: (typeof COLOR_SCHEMES)[number] = "light";

    /**
     * @description Should set data-theme attribute on <html> when applyTheme is called
     * @scenario applyTheme(scheme) with a valid ColorScheme
     * @expected <html> has data-theme equal to the provided scheme
     */
    it("should set data-theme attribute on <html> when applyTheme is called", () => {
      // Arrange
      expect(document.documentElement).not.toHaveAttribute("data-theme");

      // Act
      applyTheme(scheme);

      // Assert
      expect(document.documentElement).toHaveAttribute("data-theme", scheme);
    });

    /**
     * @description Should set html colorScheme style when applyTheme is called
     * @scenario applyTheme(scheme) with a valid ColorScheme
     * @expected <html> style.colorScheme equals the provided scheme
     */
    it("should set colorScheme style on <html> when applyTheme is called", () => {
      // Arrange
      expect(document.documentElement.style.colorScheme).toBe("");

      // Act
      applyTheme(scheme);

      // Assert
      expect(document.documentElement.style.colorScheme).toBe(scheme);
    });
  });

  describe("when called multiple times with different schemes", () => {
    /**
     * @description Should overwrite existing theme attributes and styles when applying a new scheme
     * @scenario applyTheme(firstScheme) then applyTheme(secondScheme)
     * @expected <html> data-theme and colorScheme reflect the latest applied scheme
     */
    it("should overwrite data-theme and colorScheme when applyTheme is called with a new scheme", () => {
      // Arrange
      const firstScheme: (typeof COLOR_SCHEMES)[number] = "dark";
      const secondScheme: (typeof COLOR_SCHEMES)[number] = "light";

      // Act
      applyTheme(firstScheme);
      applyTheme(secondScheme);

      // Assert
      expect(document.documentElement).toHaveAttribute(
        "data-theme",
        secondScheme,
      );
      expect(document.documentElement.style.colorScheme).toBe(secondScheme);
    });
  });
});
